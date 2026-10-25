package traefik_killswitch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newPair(t *testing.T) (gate, admin http.Handler, stateFile string) {
	t.Helper()
	stateFile = filepath.Join(t.TempDir(), "state.json")
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { _, _ = rw.Write([]byte("backend")) })
	gate, err := New(context.Background(), next, &Config{StateFile: stateFile}, "gate")
	if err != nil {
		t.Fatal(err)
	}
	admin, err = New(context.Background(), next, &Config{StateFile: stateFile, Admin: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	return gate, admin, stateFile
}

func hit(h http.Handler, host string) int {
	h.(*KillSwitch).checked = time.Time{} // skip the 1s reload throttle
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
	h.ServeHTTP(rec, req)
	return rec.Code
}

func set(t *testing.T, admin http.Handler, host, mode string, header map[string]string) int {
	t.Helper()
	body := url.Values{"host": {host}, "mode": {mode}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "http://ks.lan/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	admin.ServeHTTP(rec, req)
	return rec.Code
}

func TestSwitching(t *testing.T) {
	gate, admin, _ := newPair(t)
	if c := hit(gate, "a.lan"); c != 200 {
		t.Fatalf("no state file: got %d, want 200", c)
	}
	steps := []struct {
		host, mode, check string
		want              int
	}{
		{"a.lan", "maint", "a.lan", 503},
		{"a.lan", "maint", "b.lan:8443", 200},
		{"b.lan", "block", "b.lan:8443", 403},
		{"*", "maint", "c.lan", 503},
		{"*", "maint", "b.lan", 503}, // global wins over per-host block
		{"*", "on", "b.lan", 403},    // per-host block applies again
		{"b.lan", "on", "b.lan", 200},
		{"a.lan", "on", "a.lan", 200},
	}
	for _, s := range steps {
		if c := set(t, admin, s.host, s.mode, nil); c != http.StatusSeeOther {
			t.Fatalf("set %s=%s: got %d", s.host, s.mode, c)
		}
		if c := hit(gate, s.check); c != s.want {
			t.Fatalf("after %s=%s, %s: got %d, want %d", s.host, s.mode, s.check, c, s.want)
		}
	}
}

func TestCorruptFileKeepsLastState(t *testing.T) {
	gate, admin, stateFile := newPair(t)
	set(t, admin, "a.lan", "block", nil)
	if c := hit(gate, "a.lan"); c != 403 {
		t.Fatalf("got %d, want 403", c)
	}
	if err := os.WriteFile(stateFile, []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if c := hit(gate, "a.lan"); c != 403 {
		t.Fatalf("corrupt file reopened site: got %d, want 403", c)
	}
}

func TestAdminRejectsCrossSiteAndBadInput(t *testing.T) {
	_, admin, _ := newPair(t)
	if c := set(t, admin, "a.lan", "maint", map[string]string{"Origin": "https://evil.example"}); c != 403 {
		t.Fatalf("cross-origin post: got %d, want 403", c)
	}
	if c := set(t, admin, "a.lan", "maint", map[string]string{"Sec-Fetch-Site": "cross-site"}); c != 403 {
		t.Fatalf("cross-site post: got %d, want 403", c)
	}
	if c := set(t, admin, "a.lan", "maint", map[string]string{"Origin": "http://ks.lan"}); c != http.StatusSeeOther {
		t.Fatalf("same-origin post: got %d, want 303", c)
	}
	if c := set(t, admin, "a.lan", "nuke", nil); c != 400 {
		t.Fatalf("bad mode: got %d, want 400", c)
	}
}

func TestAdminPageEscapesHosts(t *testing.T) {
	gate, admin, _ := newPair(t)
	hit(gate, "a.lan")
	set(t, admin, `<script>x</script>`, "block", nil)
	rec := httptest.NewRecorder()
	admin.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://ks.lan/", nil))
	body := rec.Body.String()
	if strings.Contains(body, "<script>x") {
		t.Fatal("host not escaped")
	}
	if !strings.Contains(body, "a.lan") {
		t.Fatal("seen host missing from admin page")
	}
}

func TestCustomMaintenancePage(t *testing.T) {
	dir := t.TempDir()
	page := filepath.Join(dir, "page.html")
	if err := os.WriteFile(page, []byte("<h1>Back at 18:00</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}
	stateFile := filepath.Join(dir, "state.json")
	if err := os.WriteFile(stateFile, []byte(`{"a.lan":"maint"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	gate, err := New(context.Background(), nil, &Config{StateFile: stateFile, MaintenanceFile: page}, "gate")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://a.lan/", nil))
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "Back at 18:00") {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	if err := os.WriteFile(page, []byte("<h1>Back at 19:00</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://a.lan/", nil))
	if !strings.Contains(rec.Body.String(), "Back at 19:00") {
		t.Fatalf("edit not picked up: %q", rec.Body.String())
	}
	if err := os.Remove(page); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://a.lan/", nil))
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "Under maintenance") {
		t.Fatalf("missing file should fall back to built-in page: %d %q", rec.Code, rec.Body.String())
	}
}

func TestExcludeHosts(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(stateFile, []byte(`{"*":"block"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {})
	gate, err := New(context.Background(), next, &Config{StateFile: stateFile, ExcludeHosts: []string{" Auth.LAN "}}, "gate")
	if err != nil {
		t.Fatal(err)
	}
	if c := hit(gate, "auth.lan:443"); c != 200 {
		t.Fatalf("excluded host: got %d, want 200", c)
	}
	if c := hit(gate, "a.lan"); c != 403 {
		t.Fatalf("other host: got %d, want 403", c)
	}
}

func TestAdminShowsExcludedHosts(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "state.json")
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {})
	gate, err := New(context.Background(), next, &Config{StateFile: stateFile, ExcludeHosts: []string{"auth.lan"}}, "gate-excl")
	if err != nil {
		t.Fatal(err)
	}
	hit(gate, "auth.lan")
	hit(gate, "app.lan")
	admin, err := New(context.Background(), next, &Config{StateFile: stateFile, Admin: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	admin.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://ks.lan/", nil))
	body := rec.Body.String()
	alwaysOn := strings.Index(body, "Always on")
	if alwaysOn < 0 || !strings.Contains(body[alwaysOn:], "<li>auth.lan</li>") {
		t.Fatal("excluded host not listed under Always on")
	}
	if strings.Contains(body, `name="host" value="auth.lan"`) {
		t.Fatal("excluded host must not get switch buttons")
	}
	if !strings.Contains(body, `name="host" value="app.lan"`) {
		t.Fatal("normal host missing")
	}
	if c := set(t, admin, "auth.lan", "block", nil); c != http.StatusSeeOther {
		t.Fatalf("got %d", c)
	}
	if _, err := os.Stat(stateFile); err == nil {
		t.Fatal("switching an excluded host must not write state")
	}
	delete(excludedBy, "gate-excl")
}

func TestTemplates(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("maintenance.html", "default-page")
	write("downtime.html", "downtime-page")
	write("notes.txt", "not a template")
	stateFile := filepath.Join(dir, "state.json")
	gate, err := New(context.Background(), nil, &Config{StateFile: stateFile, MaintenanceFile: filepath.Join(dir, "maintenance.html")}, "gate-tpl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { delete(maintFiles, "gate-tpl"); delete(excludedBy, "gate-tpl") }()
	admin, err := New(context.Background(), nil, &Config{StateFile: stateFile, Admin: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if got := templates(); len(got) != 1 || got[0] != "downtime" {
		t.Fatalf("templates() = %v, want [downtime]", got)
	}
	body := func(host string) string {
		gate.(*KillSwitch).checked = time.Time{}
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil))
		return rec.Body.String()
	}
	post := func(host, mode, tpl string) {
		t.Helper()
		form := url.Values{"host": {host}, "mode": {mode}, "template": {tpl}}.Encode()
		req := httptest.NewRequest(http.MethodPost, "http://ks.lan/", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		admin.ServeHTTP(rec, req)
		if loc := rec.Header().Get("Location"); strings.Contains(loc, "err=") {
			t.Fatalf("post %s %s %s: %s", host, mode, tpl, loc)
		}
	}
	post("a.lan", "maint", "")
	if b := body("a.lan"); b != "default-page" {
		t.Fatalf("default: got %q", b)
	}
	post("a.lan", "maint", "downtime")
	if b := body("a.lan"); b != "downtime-page" {
		t.Fatalf("template: got %q", b)
	}
	// old plain values and unknown templates still work
	write("state.json", `{"a.lan":"maint","b.lan":"maint:gone","c.lan":"maint:../../etc/passwd"}`)
	for _, h := range []string{"a.lan", "b.lan", "c.lan"} {
		if b := body(h); b != "default-page" {
			t.Fatalf("%s: got %q, want default page", h, b)
		}
	}
	// global switch uses its own template
	write("state.json", `{"*":"maint:downtime"}`)
	if b := body("z.lan"); b != "downtime-page" {
		t.Fatalf("global template: got %q", b)
	}
	// admin refuses an unknown template
	form := url.Values{"host": {"a.lan"}, "mode": {"maint"}, "template": {"nope"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "http://ks.lan/", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	admin.ServeHTTP(rec, req)
	if !strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Fatal("unknown template accepted")
	}
	page := httptest.NewRecorder()
	admin.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "http://ks.lan/", nil))
	if !strings.Contains(page.Body.String(), `<option value="downtime"`) {
		t.Fatal("admin page has no template select")
	}
}
