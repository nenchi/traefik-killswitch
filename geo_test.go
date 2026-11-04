package traefik_killswitch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- a tiny .mmdb writer, so the reader is tested against known data ---

type tnode struct{ rec [2]int } // >=0 child node, -1 empty, <= -2 data index (-2 - i)

// writeMMDB builds an IPv6 database; IPv4 networks are stored under ::/96 like MaxMind does.
// data[i] is a raw encoded data-section value; nets maps a prefix to its data index.
func writeMMDB(t *testing.T, recordSize int, nets map[string]int, data [][]byte) []byte {
	t.Helper()
	nodes := []tnode{{rec: [2]int{-1, -1}}}
	for s, di := range nets {
		p := netip.MustParsePrefix(s)
		addr := p.Addr().As16()
		bits := p.Bits()
		if p.Addr().Is4() {
			a4 := p.Addr().As4()
			addr = [16]byte{}
			copy(addr[12:], a4[:]) // ::a.b.c.d, not the ::ffff: form As16 gives
			bits += 96
		}
		n := 0
		for i := 0; i < bits; i++ {
			bit := int(addr[i/8]>>(7-uint(i%8))) & 1
			if i == bits-1 {
				nodes[n].rec[bit] = -2 - di
				break
			}
			if nodes[n].rec[bit] < 0 {
				nodes = append(nodes, tnode{rec: [2]int{-1, -1}})
				nodes[n].rec[bit] = len(nodes) - 1
			}
			n = nodes[n].rec[bit]
		}
	}
	// data section, remembering each value's offset
	var section []byte
	offsets := []int{}
	for _, d := range data {
		offsets = append(offsets, len(section))
		section = append(section, d...)
	}
	count := len(nodes)
	val := func(r int) int {
		switch {
		case r >= 0:
			return r
		case r == -1:
			return count
		}
		return count + 16 + offsets[-2-r]
	}
	var tree []byte
	for _, nd := range nodes {
		l, r := val(nd.rec[0]), val(nd.rec[1])
		switch recordSize {
		case 24:
			tree = append(tree, byte(l>>16), byte(l>>8), byte(l), byte(r>>16), byte(r>>8), byte(r))
		case 28:
			tree = append(tree, byte(l>>16), byte(l>>8), byte(l), byte((l>>24)<<4|(r>>24)&0x0F), byte(r>>16), byte(r>>8), byte(r))
		case 32:
			tree = append(tree, byte(l>>24), byte(l>>16), byte(l>>8), byte(l), byte(r>>24), byte(r>>16), byte(r>>8), byte(r))
		}
	}
	out := append(tree, make([]byte, 16)...)
	out = append(out, section...)
	out = append(out, mmdbMarker...)
	out = append(out, emap(
		"node_count", euint(6, count),
		"record_size", euint(5, recordSize),
		"ip_version", euint(5, 6),
		"database_type", estr("Test-Country"))...)
	return out
}

func estr(s string) []byte { return append([]byte{byte(2<<5 | len(s))}, s...) }

func euint(typ, v int) []byte {
	b := []byte{}
	for x := v; x > 0; x >>= 8 {
		b = append([]byte{byte(x)}, b...)
	}
	return append([]byte{byte(typ<<5 | len(b))}, b...)
}

// emap encodes key/value pairs (values already encoded).
func emap(kv ...interface{}) []byte {
	b := []byte{byte(7<<5 | len(kv)/2)}
	for i := 0; i < len(kv); i += 2 {
		b = append(b, estr(kv[i].(string))...)
		b = append(b, kv[i+1].([]byte)...)
	}
	return b
}

// eptr is a pointer (size class 0) to data-section offset p.
func eptr(p int) []byte { return []byte{byte(1<<5 | (p>>8)&7), byte(p)} }

func testDB(t *testing.T, recordSize int) []byte {
	de := emap("country", emap("iso_code", estr("DE"), "names", emap("en", estr("Germany"))))
	// second record: an array and a bool before "country" (skip paths), country map via a pointer into the first record
	countryDE := 1 + len(estr("country"))                                                           // offset of DE's country map in record 0 (after the map byte and the key)
	es := emap("tags", []byte{1, 4, 2<<5 | 1, 'x'}, "eu", []byte{0, 7}, "country", eptr(countryDE)) // tags = [ "x" ], eu = false
	reg := emap("registered_country", emap("iso_code", estr("FR")))
	return writeMMDB(t, recordSize, map[string]int{
		"1.2.3.0/24":    0,
		"5.6.0.0/16":    1,
		"9.9.9.0/24":    2,
		"2001:db8::/32": 0,
	}, [][]byte{de, es, reg})
}

func TestMMDB(t *testing.T) {
	for _, rs := range []int{24, 28, 32} {
		db, err := parseMMDB(testDB(t, rs))
		if err != nil {
			t.Fatalf("record size %d: %v", rs, err)
		}
		for ip, want := range map[string]string{
			"1.2.3.4": "DE", "1.2.3.255": "DE", "1.2.4.1": "", "5.6.7.8": "DE", "9.9.9.9": "FR",
			"::ffff:1.2.3.4": "DE", "2001:db8::1": "DE", "2001:db9::1": "", "8.8.8.8": "",
		} {
			if got := db.country(netip.MustParseAddr(ip)); got != want {
				t.Errorf("record size %d: %s = %q, want %q", rs, ip, got, want)
			}
		}
	}
	if _, err := parseMMDB([]byte("not a database")); err == nil {
		t.Error("garbage accepted")
	}
}

// --- the gate ---

func geoGate(t *testing.T, stateFile, name string, geo *GeoConfig, exclude ...string) http.Handler {
	t.Helper()
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { _, _ = rw.Write([]byte("backend")) })
	h, err := New(context.Background(), next, &Config{StateFile: stateFile, Geo: geo, ExcludeHosts: exclude}, name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		geoMu.Lock()
		delete(geoDefault, name)
		geoBlocked = map[string]int{}
		geoMu.Unlock()
	})
	return h
}

func visit(h http.Handler, host, remote string, header map[string]string) int {
	h.(*KillSwitch).checked = time.Time{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
	req.RemoteAddr = remote
	for k, v := range header {
		req.Header.Set(k, v)
	}
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestGeoHeader(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	gate := geoGate(t, state, "geo-header", &GeoConfig{
		CountryHeader:  "CF-IPCountry",
		TrustedProxies: []string{"10.0.0.0/8, 172.16.0.1"},
		AllowNetworks:  []string{"192.168.0.0/16"},
		Countries:      []string{"de", "AT"},
	}, "vault.example.com")
	proxied := func(country string) map[string]string {
		return map[string]string{"CF-IPCountry": country, "X-Forwarded-For": "203.0.113.5"}
	}
	for _, c := range []struct {
		name, host, remote string
		header             map[string]string
		want               int
	}{
		{"allowed country via proxy", "app.example.com", "10.1.2.3:443", proxied("DE"), 200},
		{"second allowed country", "app.example.com", "10.1.2.3:443", proxied("at"), 200},
		{"other country", "app.example.com", "10.1.2.3:443", proxied("CN"), 403},
		{"no header via proxy", "app.example.com", "10.1.2.3:443", map[string]string{"X-Forwarded-For": "203.0.113.5"}, 403},
		{"direct hit with spoofed header", "app.example.com", "203.0.113.9:5555", map[string]string{"CF-IPCountry": "DE"}, 403},
		{"LAN", "app.example.com", "192.168.1.20:5555", nil, 200},
		{"LAN visitor behind the proxy", "app.example.com", "172.16.0.1:443", map[string]string{"X-Forwarded-For": "192.168.1.20", "CF-IPCountry": "CN"}, 200},
		{"spoofed XFF left of the real client", "app.example.com", "10.1.2.3:443", map[string]string{"X-Forwarded-For": "192.168.1.20, 203.0.113.5", "CF-IPCountry": "CN"}, 403},
		{"excluded host still checked", "vault.example.com", "10.1.2.3:443", proxied("CN"), 403},
	} {
		if got := visit(gate, c.host, c.remote, c.header); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
	geoMu.Lock()
	cn, unknown := geoBlocked["CN"], geoBlocked["??"]
	geoMu.Unlock()
	if cn != 3 || unknown != 2 {
		t.Errorf("blocked counts CN=%d ??=%d, want 3 and 2", cn, unknown)
	}
}

func TestGeoUnknownAllow(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	gate := geoGate(t, state, "geo-unknown", &GeoConfig{CountryHeader: "CF-IPCountry", TrustedProxies: []string{"10.0.0.0/8"},
		Countries: []string{"DE"}, Unknown: "allow"})
	if got := visit(gate, "a.example.com", "203.0.113.9:1", nil); got != 200 {
		t.Errorf("unknown=allow: direct hit got %d", got)
	}
	if got := visit(gate, "a.example.com", "10.0.0.1:1", map[string]string{"CF-IPCountry": "CN"}); got != 403 {
		t.Errorf("known other country still blocked: got %d", got)
	}
}

func TestGeoConfigErrors(t *testing.T) {
	for _, c := range []*GeoConfig{
		{},
		{CountryHeader: "CF-IPCountry"},
		{GeoIPFile: "x.mmdb", Unknown: "maybe"},
		{GeoIPFile: "x.mmdb", Countries: []string{"Germany"}},
		{GeoIPFile: "x.mmdb", AllowNetworks: []string{"not-a-net"}},
	} {
		if _, err := New(context.Background(), http.NotFoundHandler(), &Config{StateFile: "s.json", Geo: c}, "bad"); err == nil {
			t.Errorf("config %+v accepted", *c)
		}
	}
}

func TestGeoFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "country.mmdb")
	if err := os.WriteFile(file, testDB(t, 24), 0o644); err != nil {
		t.Fatal(err)
	}
	gate := geoGate(t, filepath.Join(dir, "state.json"), "geo-file", &GeoConfig{GeoIPFile: file, Countries: []string{"DE"}})
	for remote, want := range map[string]int{"1.2.3.4:1": 200, "5.6.7.8:1": 200, "9.9.9.9:1": 403, "8.8.8.8:1": 403, "[2001:db8::5]:1": 200} {
		if got := visit(gate, "a.example.com", remote, nil); got != want {
			t.Errorf("%s: got %d, want %d", remote, got, want)
		}
	}
	// header + file: a trusted proxy's header wins, the file covers requests without one
	gate2 := geoGate(t, filepath.Join(dir, "state2.json"), "geo-both", &GeoConfig{GeoIPFile: file, CountryHeader: "X-Country",
		TrustedProxies: []string{"10.0.0.0/8"}, Countries: []string{"FR"}})
	if got := visit(gate2, "a.example.com", "10.0.0.1:1", map[string]string{"X-Country": "FR", "X-Forwarded-For": "1.2.3.4"}); got != 200 {
		t.Errorf("header should win over file: got %d", got)
	}
	if got := visit(gate2, "a.example.com", "10.0.0.1:1", map[string]string{"X-Forwarded-For": "9.9.9.9"}); got != 200 {
		t.Errorf("file lookup of the forwarded client: got %d", got)
	}
	// a broken file is not fatal: unknown policy applies, and a fixed file is picked up
	gate3 := geoGate(t, filepath.Join(dir, "state3.json"), "geo-missing", &GeoConfig{GeoIPFile: filepath.Join(dir, "missing.mmdb"), Countries: []string{"DE"}})
	if got := visit(gate3, "a.example.com", "1.2.3.4:1", nil); got != 403 {
		t.Errorf("missing file: got %d, want 403 (unknown=block)", got)
	}
}

func postForm(admin http.Handler, form url.Values) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://ks.example.com/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	admin.ServeHTTP(rec, req)
	return rec
}

func TestGeoAdmin(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	gate := geoGate(t, state, "geo-admin", &GeoConfig{CountryHeader: "CF-IPCountry", TrustedProxies: []string{"10.0.0.0/8"},
		Countries: []string{"DE", "AT"}})
	admin, err := New(context.Background(), http.NotFoundHandler(), &Config{StateFile: state, Admin: true}, "geo-admin-page")
	if err != nil {
		t.Fatal(err)
	}
	from := func(c string) int {
		return visit(gate, "a.example.com", "10.0.0.1:1", map[string]string{"CF-IPCountry": c})
	}
	if from("ES") != 403 {
		t.Fatal("ES should start blocked")
	}
	page := adminPage(t, admin)
	if g, sites := strings.Index(page, `id="geo"`), strings.Index(page, "All sites"); g < 0 || g > sites {
		t.Error("Countries card should come before the site list")
	}
	for _, want := range []string{`id="geo"`, `>AT<form`, `>DE<form`, `ES <small>1</small>`, `value="ES"><button title="Allow ES permanently"`} {
		if !strings.Contains(page, want) {
			t.Errorf("admin page lacks %q", want)
		}
	}

	defer func() { now = time.Now }()
	base := time.Date(2026, 11, 4, 12, 0, 0, 0, time.Local)
	now = func() time.Time { return base }
	if rec := postForm(admin, url.Values{"action": {"geo-allow"}, "country": {"es"}, "days": {"7"}}); rec.Code != http.StatusSeeOther ||
		strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Fatalf("allow ES: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if from("ES") != 200 {
		t.Error("ES allowed for 7 days but blocked")
	}
	if !strings.Contains(adminPage(t, admin), "ES <small>until Wed 11 Nov 12:00</small>") {
		t.Error("admin page doesn't show ES's end")
	}
	// permanent DE can't be downgraded to temporary by accident
	if loc := postForm(admin, url.Values{"action": {"geo-allow"}, "country": {"DE"}, "days": {"1"}}).Header().Get("Location"); !strings.Contains(loc, "already+allowed+permanently") {
		t.Errorf("DE downgrade not refused: %s", loc)
	}
	for _, bad := range []url.Values{{"action": {"geo-allow"}, "country": {"Spain"}}, {"action": {"geo-allow"}, "country": {"PT"}, "days": {"0"}}} {
		if loc := postForm(admin, bad).Header().Get("Location"); !strings.Contains(loc, "err=") {
			t.Errorf("%v accepted", bad)
		}
	}
	postForm(admin, url.Values{"action": {"geo-remove"}, "country": {"DE"}})
	if from("DE") != 403 || from("AT") != 200 {
		t.Error("after removing DE: DE should be blocked, AT allowed")
	}
	// the window ends: checkGeo drops ES and logs it
	now = func() time.Time { return base.AddDate(0, 0, 8) }
	gate.(*KillSwitch).checked = time.Time{}
	gate.(*KillSwitch).checkGeo(now())
	b, _ := os.ReadFile(state)
	if strings.Contains(string(b), "ES") {
		t.Errorf("expired ES still in state: %s", b)
	}
	if from("ES") != 403 {
		t.Error("ES should be blocked after its time ran out")
	}
	hist, _ := os.ReadFile(state + ".history")
	for _, want := range []string{"geo: ES allowed until Wed 11 Nov 12:00", "geo: DE removed", "geo: ES no longer allowed (time is up)"} {
		if !strings.Contains(string(hist), want) {
			t.Errorf("history lacks %q:\n%s", want, hist)
		}
	}
	// removing everything leaves only allowNetworks, and says so
	postForm(admin, url.Values{"action": {"geo-remove"}, "country": {"AT"}})
	if from("AT") != 403 || !strings.Contains(adminPage(t, admin), "No country is allowed") {
		t.Error("empty list should block every country and warn")
	}
	// switched off: everyone passes, the list is kept; on again: enforced again
	if !strings.Contains(adminPage(t, admin), `value="geo-off">turn off`) {
		t.Error("no turn-off button")
	}
	postForm(admin, url.Values{"action": {"geo-off"}})
	if from("CN") != 200 || !strings.Contains(adminPage(t, admin), "Off: every country gets through") {
		t.Error("check switched off, but CN still refused or page doesn't say so")
	}
	postForm(admin, url.Values{"action": {"geo-on"}})
	if from("CN") != 403 {
		t.Error("check switched on again, but CN passes")
	}
	if rec := postForm(admin, url.Values{"action": {"geo-bogus"}, "country": {"DE"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown geo action: got %d", rec.Code)
	}
	hist, _ = os.ReadFile(state + ".history")
	for _, want := range []string{"geo: country check switched OFF", "geo: country check switched on"} {
		if !strings.Contains(string(hist), want) {
			t.Errorf("history lacks %q", want)
		}
	}
	// @geo is not a host
	if !strings.Contains(adminPage(t, admin), `id="geo"`) || strings.Contains(adminPage(t, admin), `value="@geo"`) {
		t.Error("@geo listed as a host")
	}
	if rec := postForm(admin, url.Values{"host": {"@geo"}, "mode": {"block"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("switching @geo as a host: got %d", rec.Code)
	}
}

func TestNoGeoNoCard(t *testing.T) {
	_, admin, _ := newPair(t)
	if geoEnabled() {
		t.Skip("another test left a geo gate registered")
	}
	if strings.Contains(adminPage(t, admin), `id="geo"`) {
		t.Error("Countries card shown without any geo gate")
	}
}

func adminPage(t *testing.T, admin http.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	admin.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://ks.example.com/", nil))
	return rec.Body.String()
}

// MaxMind's official test files: written by their real writer (pointers, shared data), see testdata/README.md.
func TestMaxMindTestFile(t *testing.T) {
	buf, err := os.ReadFile("testdata/GeoLite2-Country-Test.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	db, err := parseMMDB(buf)
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]string{
		"2.125.160.216": "GB", "81.2.69.160": "GB", "89.160.20.112": "SE", "89.160.20.200": "SE", "216.160.83.56": "US",
		"67.43.156.1": "BT", "111.235.160.1": "CN", "202.196.224.1": "PH", "217.65.48.1": "GI",
		"2001:218::1": "JP", "2001:220::1": "KR", "2001:238::1": "TW", "2001:2e0::1": "HK",
		"::ffff:81.2.69.160": "GB", "8.8.8.8": "", "10.0.0.1": "", "2001:db8::1": "",
	} {
		if got := db.country(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s = %q, want %q", ip, got, want)
		}
	}
}

// Broken and hostile files must never panic or hang: they either fail to load or answer "".
func TestBrokenMMDBFiles(t *testing.T) {
	files, _ := filepath.Glob("testdata/*.mmdb")
	ips := []string{"1.1.1.1", "1.1.1.3", "1.1.1.32", "81.2.69.160", "::1.1.1.1", "2001:218::1", "::2:0:0", "255.255.255.255"}
	for _, f := range files {
		buf, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, cut := range []int{len(buf), len(buf) / 2, len(buf) - 20} { // whole file and truncated copies
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s (%d bytes): panic: %v", f, cut, r)
					}
				}()
				db, err := parseMMDB(buf[:cut])
				if err != nil {
					return
				}
				for _, ip := range ips {
					db.country(netip.MustParseAddr(ip))
				}
			}()
		}
	}
}

// A record that is a pointer to itself: an unguarded reader recurses until Go's stack overflows,
// which is fatal (not a recoverable panic) and would take Traefik down.
func TestSelfPointer(t *testing.T) {
	db, err := parseMMDB(writeMMDB(t, 24, map[string]int{"1.2.3.0/24": 0}, [][]byte{eptr(0)}))
	if err != nil {
		t.Fatal(err)
	}
	if got := db.country(netip.MustParseAddr("1.2.3.4")); got != "" {
		t.Errorf("got %q", got)
	}
}
