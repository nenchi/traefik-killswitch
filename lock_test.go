package traefik_killswitch

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RFC 7914 section 11 test vectors for PBKDF2-HMAC-SHA256.
func TestPBKDF2Vectors(t *testing.T) {
	for _, c := range []struct {
		iter int
		want string
	}{
		{1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
		{4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
	} {
		if got := hex.EncodeToString(pbkdf2SHA256([]byte("password"), []byte("salt"), c.iter)); got != c.want {
			t.Errorf("iter %d: %s, want %s", c.iter, got, c.want)
		}
	}
}

func TestHashPassword(t *testing.T) {
	h, err := hashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(h, "correct") || !strings.HasPrefix(h, "pbkdf2-sha256$") {
		t.Fatalf("bad hash %q", h)
	}
	h2, _ := hashPassword("correct horse")
	if h == h2 {
		t.Error("same hash twice: salt missing")
	}
	if !checkHash(h, "correct horse") || checkHash(h, "wrong horse") || checkHash("garbage", "x") || checkHash("pbkdf2-sha256$0$a$b", "x") {
		t.Error("checkHash wrong")
	}
}

func lockGate(t *testing.T, state, name string, cfg *Config) *KillSwitch {
	t.Helper()
	cfg.StateFile = state
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "" {
			rw.WriteHeader(http.StatusTeapot) // the lock's password must not reach the app
			return
		}
		_, _ = rw.Write([]byte("backend"))
	})
	h, err := New(context.Background(), next, cfg, name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		geoMu.Lock()
		delete(lockGates, name)
		delete(gateAllow, name)
		delete(geoDefault, name)
		geoBlocked = map[string]int{}
		geoMu.Unlock()
		loginMu.Lock()
		failures = map[string]*failCount{}
		loginCache = map[[32]byte]time.Time{}
		loginMu.Unlock()
	})
	return h.(*KillSwitch)
}

type reqOpt struct {
	scheme, remote, user, pass string
	header                     map[string]string
}

func send(k *KillSwitch, host string, o reqOpt) *httptest.ResponseRecorder {
	resetThrottle(k) // skip the 1s reload throttle
	if o.scheme == "" {
		o.scheme = "https"
	}
	if o.remote == "" {
		o.remote = "203.0.113.7:4444"
	}
	req := httptest.NewRequest(http.MethodGet, o.scheme+"://"+host+"/", nil)
	req.RemoteAddr = o.remote
	if o.user != "" {
		req.SetBasicAuth(o.user, o.pass)
	}
	for k, v := range o.header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	k.ServeHTTP(rec, req)
	return rec
}

func writeTestState(t *testing.T, path string, st map[string]string) {
	t.Helper()
	k := &KillSwitch{stateFile: path}
	if err := k.writeState(func(s map[string]string) {
		for key, v := range st {
			s[key] = v
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLockGate(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	hash, _ := hashPassword("s3cret-pass")
	writeTestState(t, state, map[string]string{
		groupPrefix + "family":           "alice:" + hash,
		lockPrefix + "wiki.example.com":  "family",
		lockPrefix + "vault.example.com": "family",
		"maint.example.com":              "maint",
		lockPrefix + "maint.example.com": "family",
		"lan.example.com":                "private",
	})
	gate := lockGate(t, state, "lock-gate", &Config{Locks: &LockConfig{Enabled: true, MaxFailures: 3},
		AllowNetworks: []string{"192.168.0.0/16"}, TrustedProxies: []string{"10.0.0.0/8"}, ExcludeHosts: []string{"vault.example.com"}})

	rec := send(gate, "wiki.example.com", reqOpt{})
	if rec.Code != 401 || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `Basic realm="wiki.example.com"`) {
		t.Fatalf("no login: %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	if c := send(gate, "wiki.example.com", reqOpt{user: "alice", pass: "s3cret-pass"}).Code; c != 200 {
		t.Errorf("right password: %d (418 = Authorization reached the app)", c)
	}
	if c := send(gate, "wiki.example.com", reqOpt{scheme: "http", user: "alice", pass: "s3cret-pass"}).Code; c != 403 {
		t.Errorf("plain HTTP must not ask for a password: %d", c)
	}
	if c := send(gate, "wiki.example.com", reqOpt{scheme: "http", remote: "10.1.1.1:1", user: "alice", pass: "s3cret-pass",
		header: map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-For": "203.0.113.50"}}).Code; c != 200 {
		t.Errorf("HTTPS at a trusted proxy: %d", c)
	}
	if c := send(gate, "wiki.example.com", reqOpt{scheme: "http", remote: "203.0.113.9:1", user: "alice", pass: "s3cret-pass",
		header: map[string]string{"X-Forwarded-Proto": "https"}}).Code; c != 403 {
		t.Errorf("X-Forwarded-Proto from an untrusted client was believed: %d", c)
	}
	if c := send(gate, "wiki.example.com", reqOpt{remote: "192.168.1.20:1"}).Code; c != 200 {
		t.Errorf("LAN should skip the lock: %d", c)
	}
	if c := send(gate, "vault.example.com", reqOpt{}).Code; c != 200 {
		t.Errorf("excluded host locked: %d", c)
	}
	if c := send(gate, "maint.example.com", reqOpt{user: "alice", pass: "s3cret-pass"}).Code; c != 503 {
		t.Errorf("maint must win over the lock: %d", c)
	}
	if c := send(gate, "lan.example.com", reqOpt{}).Code; c != 403 {
		t.Errorf("private from outside: %d", c)
	}
	if c := send(gate, "lan.example.com", reqOpt{remote: "192.168.1.20:1"}).Code; c != 200 {
		t.Errorf("private from LAN: %d", c)
	}
	// brute force: 3 wrong passwords, then 429 even with the right one; other addresses unaffected
	for i := 0; i < 3; i++ {
		if c := send(gate, "wiki.example.com", reqOpt{user: "alice", pass: "nope"}).Code; c != 401 {
			t.Fatalf("wrong password %d: %d", i, c)
		}
	}
	rec = send(gate, "wiki.example.com", reqOpt{user: "alice", pass: "s3cret-pass"})
	if rec.Code != 429 || rec.Header().Get("Retry-After") == "" {
		t.Errorf("after 3 failures: %d", rec.Code)
	}
	if c := send(gate, "wiki.example.com", reqOpt{remote: "203.0.113.99:1", user: "alice", pass: "s3cret-pass"}).Code; c != 200 {
		t.Errorf("other address banned too: %d", c)
	}
	defer func() { now = time.Now }()
	now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	if c := send(gate, "wiki.example.com", reqOpt{user: "alice", pass: "s3cret-pass"}).Code; c != 200 {
		t.Errorf("ban should end after banMinutes: %d", c)
	}
	now = time.Now

	// a gate without locks ignores lock state
	plain := lockGate(t, state, "lock-plain", &Config{})
	if c := send(plain, "wiki.example.com", reqOpt{}).Code; c != 200 {
		t.Errorf("gate without locks: %d", c)
	}
	if _, err := New(context.Background(), http.NotFoundHandler(), &Config{StateFile: state, Locks: &LockConfig{Enabled: true, MaxFailures: -1}}, "bad"); err == nil {
		t.Error("negative maxFailures accepted")
	}
	if lp, _ := newLockPolicy(&LockConfig{}); lp != nil {
		t.Error("locks without enabled: true should stay off")
	}
}

func TestLockWithGeo(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	hash, _ := hashPassword("s3cret-pass")
	writeTestState(t, state, map[string]string{
		groupPrefix + "travel":            "me:" + hash,
		lockPrefix + "photos.example.com": "travel|outside",
		lockPrefix + "admin.example.com":  "travel",
	})
	gate := lockGate(t, state, "lock-geo", &Config{Locks: &LockConfig{Enabled: true},
		Geo: &GeoConfig{CountryHeader: "CF-IPCountry", TrustedProxies: []string{"10.0.0.0/8"}, Countries: []string{"DE"}}})
	from := func(host, country, pass string) int {
		o := reqOpt{remote: "10.0.0.1:1", header: map[string]string{"CF-IPCountry": country, "X-Forwarded-For": "203.0.113.5"}}
		if pass != "" {
			o.user = "me"
			o.pass = pass
		}
		return send(gate, host, o).Code
	}
	for _, c := range []struct {
		name, host, country, pass string
		want                      int
	}{
		{"outside lock, allowed country: no password", "photos.example.com", "DE", "", 200},
		{"outside lock, other country: asked", "photos.example.com", "ES", "", 401},
		{"outside lock, other country, logged in", "photos.example.com", "ES", "s3cret-pass", 200},
		{"always lock, allowed country: asked", "admin.example.com", "DE", "", 401},
		{"always lock, allowed country, logged in", "admin.example.com", "DE", "s3cret-pass", 200},
		{"always lock, other country: refused before any prompt", "admin.example.com", "ES", "s3cret-pass", 403},
		{"no lock, other country", "other.example.com", "ES", "", 403},
	} {
		if got := from(c.host, c.country, c.pass); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestLockAdmin(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	admin, err := New(context.Background(), http.NotFoundHandler(), &Config{StateFile: state, Admin: true}, "lock-admin-page")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(adminPage(t, admin), `id="locks"`) {
		t.Fatal("Locks card without any gate with locks")
	}
	lockGate(t, state, "lock-admin-gate", &Config{Locks: &LockConfig{Enabled: true}, ExcludeHosts: []string{"ks.example.com"}})
	page := adminPage(t, admin)
	if !strings.Contains(page, `id="locks"`) || !strings.Contains(page, "No lock groups yet") {
		t.Fatal("Locks card missing")
	}
	post := func(v url.Values) string { return postForm(admin, v).Header().Get("Location") }
	if loc := post(url.Values{"action": {"lock-user-set"}, "group": {"family"}, "user": {"alice"}, "password": {"short"}}); !strings.Contains(loc, "err=") {
		t.Error("short password accepted")
	}
	if loc := post(url.Values{"action": {"lock-user-set"}, "group": {"fam ily"}, "user": {"alice"}, "password": {"long-enough"}}); !strings.Contains(loc, "err=") {
		t.Error("bad group name accepted")
	}
	if loc := post(url.Values{"action": {"lock-user-set"}, "group": {"family"}, "user": {"alice"}, "password": {"first-password"}}); strings.Contains(loc, "err=") {
		t.Fatalf("set user: %s", loc)
	}
	b, _ := os.ReadFile(state)
	if strings.Contains(string(b), "first-password") || !strings.Contains(string(b), `alice:pbkdf2-sha256$`) {
		t.Errorf("state should hold a hash, not the password: %s", b)
	}
	// lock a site, then the group can't be deleted / emptied
	if loc := post(url.Values{"action": {"lock"}, "host": {"wiki.example.com"}, "lock": {"family"}}); strings.Contains(loc, "err=") {
		t.Fatalf("lock site: %s", loc)
	}
	if !strings.Contains(adminPage(t, admin), "🔒 family") {
		t.Error("row doesn't show the lock")
	}
	for _, v := range []url.Values{
		{"action": {"lock-group-delete"}, "group": {"family"}},
		{"action": {"lock-user-remove"}, "group": {"family"}, "user": {"alice"}},
		{"action": {"lock"}, "host": {"ks.example.com"}, "lock": {"family"}},
		{"action": {"lock"}, "host": {"*"}, "lock": {"family"}},
		{"action": {"lock"}, "host": {"wiki.example.com"}, "lock": {"nope"}},
		{"action": {"lock"}, "host": {"wiki.example.com"}, "lock": {"family"}, "when": {"outside"}}, // no geo gate
	} {
		if loc := post(v); !strings.Contains(loc, "err=") {
			t.Errorf("%v accepted", v)
		}
	}
	post(url.Values{"action": {"lock-user-set"}, "group": {"family"}, "user": {"alice"}, "password": {"second-password"}})
	post(url.Values{"action": {"lock-user-set"}, "group": {"family"}, "user": {"bob"}, "password": {"bobs-password"}})
	if loc := post(url.Values{"action": {"lock-user-remove"}, "group": {"family"}, "user": {"bob"}}); strings.Contains(loc, "err=") {
		t.Errorf("remove bob: %s", loc)
	}
	post(url.Values{"action": {"lock"}, "host": {"wiki.example.com"}, "lock": {""}})
	if loc := post(url.Values{"action": {"lock-group-delete"}, "group": {"family"}}); strings.Contains(loc, "err=") {
		t.Errorf("delete unused group: %s", loc)
	}
	b, _ = os.ReadFile(state)
	if strings.Contains(string(b), "@lock") {
		t.Errorf("leftover lock state: %s", b)
	}
	hist, _ := os.ReadFile(state + ".history")
	for _, want := range []string{"lock: user alice added to family", "lock: wiki.example.com locked with family",
		"lock: password changed for alice in family", "lock: user bob removed from family", "lock: wiki.example.com unlocked", "lock: group family deleted"} {
		if !strings.Contains(string(hist), want) {
			t.Errorf("history lacks %q", want)
		}
	}
	for _, secret := range []string{"first-password", "second-password", "bobs-password"} {
		if strings.Contains(string(hist), secret) {
			t.Errorf("history contains a password")
		}
	}
}

func TestPrivateMode(t *testing.T) {
	gate, admin, _ := newPair(t)
	if c := set(t, admin, "a.lan", "private", nil); c != http.StatusSeeOther {
		t.Fatalf("set private: %d", c)
	}
	if hit(gate, "a.lan") != 403 {
		t.Error("private without allowNetworks should refuse everyone")
	}
	if !strings.Contains(adminPage(t, admin), "private works like block") {
		t.Error("no hint that private needs allowNetworks")
	}
}
