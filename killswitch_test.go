package traefik_killswitch

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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

func TestSchedule(t *testing.T) {
	gate, admin, stateFile := newPair(t)
	base := time.Date(2026, 10, 26, 21, 0, 0, 0, time.Local)
	clock := base
	now = func() time.Time { return clock }
	defer func() { now = time.Now }()

	post := func(form url.Values) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "http://ks.lan/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		admin.ServeHTTP(rec, req)
		return rec.Header().Get("Location")
	}
	schedule := func(host, mode, from, to string) string {
		return post(url.Values{"host": {host}, "action": {"schedule"}, "mode": {mode}, "from": {from}, "to": {to}})
	}

	if loc := schedule("a.lan", "block", "2026-10-26T22:00", "2026-10-27T02:00"); strings.Contains(loc, "err=") {
		t.Fatalf("schedule rejected: %s", loc)
	}
	steps := []struct {
		at   time.Duration
		want int
	}{
		{0, 200},                         // 21:00 before the window
		{time.Hour, 403},                 // 22:00 start is inclusive
		{5*time.Hour - time.Second, 403}, // 01:59:59
		{5 * time.Hour, 200},             // 02:00 end is exclusive
	}
	for _, s := range steps {
		clock = base.Add(s.at)
		if c := hit(gate, "a.lan"); c != s.want {
			t.Fatalf("at %s: got %d, want %d", clock.Format(timeFmt), c, s.want)
		}
	}

	// switching the normal mode keeps the window
	clock = base
	post(url.Values{"host": {"a.lan"}, "mode": {"maint"}})
	if c := hit(gate, "a.lan"); c != 503 {
		t.Fatalf("normal mode maint: got %d", c)
	}
	clock = base.Add(90 * time.Minute)
	if c := hit(gate, "a.lan"); c != 403 {
		t.Fatalf("window lost after mode change: got %d", c)
	}

	// cancel
	post(url.Values{"host": {"a.lan"}, "action": {"unschedule"}})
	if c := hit(gate, "a.lan"); c != 503 {
		t.Fatalf("after cancel: got %d, want normal mode 503", c)
	}

	// a maint window sets Retry-After to the window's end
	clock = base
	schedule("b.lan", "maint", "2026-10-26T20:00", "2026-10-26T21:30")
	gate.(*KillSwitch).checked = time.Time{}
	rec := httptest.NewRecorder()
	now = time.Now // Retry-After uses the real clock
	clock = time.Now()
	from, to := clock.Add(-time.Minute).Format("2006-01-02T15:04"), clock.Add(time.Hour).Format("2006-01-02T15:04")
	schedule("c.lan", "maint", from, to)
	gate.(*KillSwitch).checked = time.Time{}
	gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://c.lan/", nil))
	if rec.Code != 503 {
		t.Fatalf("active maint window: got %d", rec.Code)
	}
	if ra, _ := strconv.Atoi(rec.Header().Get("Retry-After")); ra < 3000 || ra > 3700 {
		t.Fatalf("Retry-After %q, want about an hour", rec.Header().Get("Retry-After"))
	}
	now = func() time.Time { return clock }

	// validation
	for _, bad := range [][4]string{
		{"a.lan", "on", "2026-10-26T22:00", "2026-10-27T02:00"},
		{"a.lan", "block", "2026-10-27T02:00", "2026-10-26T22:00"},
		{"a.lan", "block", "2020-01-01T00:00", "2020-01-01T01:00"},
		{"a.lan", "block", "", "2026-10-27T02:00"},
	} {
		if loc := schedule(bad[0], bad[1], bad[2], bad[3]); !strings.Contains(loc, "err=") {
			t.Fatalf("accepted invalid schedule %v", bad)
		}
	}

	// old plain values still parse, and the state file stays readable JSON
	b, err := os.ReadFile(stateFile)
	if err != nil || !strings.Contains(string(b), `"c.lan": "on|maint|`) {
		t.Fatalf("state file: %s %v", b, err)
	}
	if e := parseEntry("maint:downtime"); e.mode != "maint" || e.tpl != "downtime" || e.scheduled() {
		t.Fatalf("plain value parsed as %+v", e)
	}
}

func TestExpiredWindowIsDropped(t *testing.T) {
	_, admin, stateFile := newPair(t)
	if err := os.WriteFile(stateFile, []byte(`{"a.lan":"maint|block|2020-01-01T00:00:00Z|2020-01-01T01:00:00Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	set(t, admin, "a.lan", "block", nil)
	b, _ := os.ReadFile(stateFile)
	if strings.Contains(string(b), "2020") {
		t.Fatalf("expired window kept: %s", b)
	}
}

func TestLogging(t *testing.T) {
	var buf bytes.Buffer
	infoLog = log.New(&buf, "", 0)
	defer func() { infoLog = log.New(os.Stdout, "", 0) }()
	gate, admin, _ := newPair(t)
	k := gate.(*KillSwitch)

	post := func(form url.Values) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "http://ks.lan/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("alice", "secret")
		req.Header.Set("X-Real-Ip", "192.0.2.7")
		rec := httptest.NewRecorder()
		admin.ServeHTTP(rec, req)
		if loc := rec.Header().Get("Location"); strings.Contains(loc, "err=") {
			t.Fatalf("post rejected: %s", loc)
		}
	}
	expectLog := func(want string) {
		t.Helper()
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("log missing %q, got:\n%s", want, buf.String())
		}
	}

	post(url.Values{"host": {"a.lan"}, "mode": {"maint"}})
	expectLog(" INF KILL-SWITCH: a.lan set to maint by alice from 192.0.2.7")
	post(url.Values{"host": {"*"}, "mode": {"on"}})
	expectLog("KILL-SWITCH: all sites set to on by alice")

	from := time.Now().Add(time.Hour).Truncate(time.Minute)
	to := from.Add(2 * time.Hour)
	post(url.Values{"host": {"b.lan"}, "action": {"schedule"}, "mode": {"block"},
		"from": {from.Format("2006-01-02T15:04")}, "to": {to.Format("2006-01-02T15:04")}})
	expectLog("KILL-SWITCH: schedule created for b.lan: block from " + from.Format(timeFmt))

	k.checked = time.Time{}
	k.checkWindows(from.Add(time.Second))
	expectLog("KILL-SWITCH: schedule started for b.lan: block until " + to.Format(timeFmt))
	expectLog("by alice)")
	n := strings.Count(buf.String(), "schedule started")
	k.checkWindows(from.Add(2 * time.Second))
	if strings.Count(buf.String(), "schedule started") != n {
		t.Fatal("start logged twice")
	}
	k.checkWindows(to)
	expectLog("KILL-SWITCH: schedule ended for b.lan: back to on")

	// a window first seen while already running (Traefik restarted mid-window)
	announcedMu.Lock()
	announced = map[string]time.Time{}
	announcedMu.Unlock()
	k.checkWindows(from.Add(30 * time.Minute))
	expectLog("KILL-SWITCH: schedule active since " + from.Format(timeFmt) + " for b.lan")

	post(url.Values{"host": {"b.lan"}, "action": {"unschedule"}})
	expectLog("KILL-SWITCH: schedule cancelled for b.lan by alice")
}

func TestHostsFromRule(t *testing.T) {
	cases := map[string]string{
		"Host(`a.lan`)":                              "a.lan",
		"Host(`A.lan`) || Host(`b.lan`)":             "a.lan b.lan",
		"Host(`a.lan`, `b.lan`) && PathPrefix(`/x`)": "a.lan b.lan",
		"HostRegexp(`.+`) || HostSNI(`x`)":           "",
		`Host("q.lan")`:                              "q.lan",
	}
	for rule, want := range cases {
		if got := strings.Join(hostsFromRule(rule), " "); got != want {
			t.Errorf("%s: got %q, want %q", rule, got, want)
		}
	}
}

func TestRouterCheck(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		switch {
		case req.URL.Path == "/api/http/routers" && req.URL.Query().Get("page") == "1":
			rw.Header().Set("X-Next-Page", "2")
			_, _ = rw.Write([]byte(`[{"name":"a@file","rule":"Host(` + "`a.lan`" + `)","status":"enabled","middlewares":["gate-rc"]},
				{"name":"bc@docker","rule":"Host(` + "`b.lan`" + `) || Host(` + "`c.lan`" + `)","status":"enabled","middlewares":["chain1@file"]}]`))
		case req.URL.Path == "/api/http/routers":
			rw.Header().Set("X-Next-Page", "1")
			_, _ = rw.Write([]byte(`[{"name":"d@docker","rule":"Host(` + "`d.lan`" + `)","status":"enabled","middlewares":["auth@file"]},
				{"name":"c2@docker","rule":"Host(` + "`c.lan`" + `) && PathPrefix(` + "`/api`" + `)","status":"enabled"},
				{"name":"off@docker","rule":"Host(` + "`off.lan`" + `)","status":"disabled","middlewares":["gate-rc"]}]`))
		case req.URL.Path == "/api/http/middlewares":
			_, _ = rw.Write([]byte(`[{"name":"chain1@file","chain":{"middlewares":["gate-rc"]}},{"name":"auth@file"}]`))
		default:
			http.NotFound(rw, req)
		}
	}))
	defer api.Close()
	stateFile := filepath.Join(t.TempDir(), "state.json")
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {})
	if _, err := New(context.Background(), next, &Config{StateFile: stateFile}, "gate-rc"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		seenMu.Lock()
		delete(excludedBy, "gate-rc")
		delete(maintFiles, "gate-rc")
		seenMu.Unlock()
	}()
	admin, err := New(context.Background(), next, &Config{StateFile: stateFile, Admin: true, APIURL: api.URL + "/"}, "admin-rc")
	if err != nil {
		t.Fatal(err)
	}
	// chain1@file contains "gate-rc" without a provider; it resolves to gate-rc@file, so register that too
	seenMu.Lock()
	excludedBy["gate-rc@file"] = nil
	seenMu.Unlock()
	defer func() { seenMu.Lock(); delete(excludedBy, "gate-rc@file"); seenMu.Unlock() }()

	routes, err := admin.(*KillSwitch).hostRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if !routes["a.lan"].protected() || !routes["b.lan"].protected() {
		t.Fatalf("a/b should be protected: %+v", routes)
	}
	if routes["c.lan"].protected() || strings.Join(routes["c.lan"].unprotected, ",") != "c2@docker" {
		t.Fatalf("c.lan has an unprotected second router: %+v", routes["c.lan"])
	}
	if _, ok := routes["off.lan"]; ok {
		t.Fatal("disabled router counted")
	}

	post := func(host, mode, action string) string {
		form := url.Values{"host": {host}, "mode": {mode}, "action": {action}}
		if action == "schedule" {
			form.Set("from", "2030-01-01T00:00")
			form.Set("to", "2030-01-01T01:00")
		}
		req := httptest.NewRequest(http.MethodPost, "http://ks.lan/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		admin.ServeHTTP(rec, req)
		return rec.Header().Get("Location")
	}
	for _, c := range []struct{ host, mode, action, want string }{
		{"a.lan", "block", "", ""},
		{"b.lan", "maint", "", ""},
		{"zz.lan", "block", "", "No+Traefik+router"},
		{"d.lan", "block", "", "d%40docker"},
		{"d.lan", "maint", "schedule", "d%40docker"},
		{"d.lan", "on", "", ""},         // switching on is always allowed
		{"d.lan", "", "unschedule", ""}, // and so is cancelling
		{"*", "block", "", ""},
	} {
		loc := post(c.host, c.mode, c.action)
		if c.want == "" && strings.Contains(loc, "err=") || c.want != "" && !strings.Contains(loc, c.want) {
			t.Errorf("%s %s %s: redirect %q, want %q", c.host, c.mode, c.action, loc, c.want)
		}
	}
	rec := httptest.NewRecorder()
	admin.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://ks.lan/", nil))
	page := rec.Body.String()
	np := strings.Index(page, "Not protected")
	if np < 0 || !strings.Contains(page[np:], "<li>d.lan") || !strings.Contains(page[np:], "<li>c.lan") {
		t.Fatal("unprotected hosts not listed")
	}
	if !strings.Contains(page[:np], `value="a.lan"`) {
		t.Fatal("protected host from the API not listed before any traffic")
	}
}

func TestUnseenHostWarnsWithoutAPI(t *testing.T) {
	_, admin, _ := newPair(t)
	form := url.Values{"host": {"never-seen.lan"}, "mode": {"block"}}
	req := httptest.NewRequest(http.MethodPost, "http://ks.lan/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	admin.ServeHTTP(rec, req)
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "warn=") || strings.Contains(loc, "err=") {
		t.Fatalf("want a warning, got %q", loc)
	}
}

func TestRepeatingWindow(t *testing.T) {
	// Every Sunday 03:00–04:00 local, first on Sun 18 Oct 2026; Europe drops DST on Sun 25 Oct.
	loc := time.Local
	e := parseEntry(entry{mode: "on", sMode: "block", repeat: "weekly",
		from: time.Date(2026, 10, 18, 3, 0, 0, 0, loc), to: time.Date(2026, 10, 18, 4, 0, 0, 0, loc)}.String())
	if e.repeat != "weekly" || e.when() != "every Sunday 03:00–04:00" {
		t.Fatalf("round trip: %+v %q", e, e.when())
	}
	for _, c := range []struct {
		at     time.Time
		active bool
		next   string
	}{
		{time.Date(2026, 10, 18, 2, 59, 0, 0, loc), false, "Sun 18 Oct 03:00"},
		{time.Date(2026, 10, 18, 3, 30, 0, 0, loc), true, "Sun 18 Oct 03:00"},
		{time.Date(2026, 10, 20, 12, 0, 0, 0, loc), false, "Sun 25 Oct 03:00"},
		{time.Date(2026, 10, 25, 3, 30, 0, 0, loc), true, "Sun 25 Oct 03:00"},
		{time.Date(2026, 10, 25, 4, 0, 0, 0, loc), false, "Sun 01 Nov 03:00"},
		{time.Date(2027, 4, 4, 3, 10, 0, 0, loc), true, "Sun 04 Apr 03:00"},
	} {
		s, end := e.window(c.at)
		if e.active(c.at) != c.active || s.Format(timeFmt) != c.next || end.Sub(s) != time.Hour {
			t.Errorf("at %s: active=%v window %s–%s, want active=%v start %s",
				c.at.Format(timeFmt), e.active(c.at), s.Format(timeFmt), end.Format(timeFmt), c.active, c.next)
		}
		if e.ended(c.at) {
			t.Errorf("a repeating window never ends")
		}
	}
	daily := entry{sMode: "maint", repeat: "daily",
		from: time.Date(2026, 10, 1, 23, 30, 0, 0, loc), to: time.Date(2026, 10, 2, 0, 30, 0, 0, loc)}
	if !daily.active(time.Date(2026, 12, 24, 0, 10, 0, 0, loc)) || daily.active(time.Date(2026, 12, 24, 0, 31, 0, 0, loc)) {
		t.Error("daily window across midnight")
	}
}

func TestHistoryCleanupAndRepeats(t *testing.T) {
	var buf bytes.Buffer
	infoLog = log.New(&buf, "", 0)
	defer func() { infoLog = log.New(os.Stdout, "", 0) }()
	gate, admin, stateFile := newPair(t)
	k := gate.(*KillSwitch)
	clock := time.Date(2026, 11, 2, 9, 0, 0, 0, time.Local)
	now = func() time.Time { return clock }
	defer func() { now = time.Now }()
	announcedMu.Lock()
	announced = map[string]time.Time{}
	announcedMu.Unlock()

	post := func(form url.Values) string {
		req := httptest.NewRequest(http.MethodPost, "http://ks.lan/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("bob", "x")
		rec := httptest.NewRecorder()
		admin.ServeHTTP(rec, req)
		return rec.Header().Get("Location")
	}
	// one-off 10:00–11:00 and a daily 02:00–03:00 repeat
	if loc := post(url.Values{"host": {"a.lan"}, "action": {"schedule"}, "mode": {"block"}, "from": {"2026-11-02T10:00"}, "to": {"2026-11-02T11:00"}}); strings.Contains(loc, "err=") {
		t.Fatal(loc)
	}
	if loc := post(url.Values{"host": {"b.lan"}, "action": {"schedule"}, "mode": {"maint"}, "repeat": {"daily"}, "from": {"2026-11-01T02:00"}, "to": {"2026-11-01T03:00"}}); strings.Contains(loc, "err=") {
		t.Fatalf("repeating window starting in the past must be accepted: %s", loc)
	}
	if loc := post(url.Values{"host": {"b.lan"}, "action": {"schedule"}, "mode": {"maint"}, "repeat": {"daily"}, "from": {"2026-11-01T02:00"}, "to": {"2026-11-02T03:00"}}); !strings.Contains(loc, "err=") {
		t.Fatal("daily window longer than a day accepted")
	}
	tick := func(at time.Time) {
		clock = at
		k.checked = time.Time{}
		k.checkWindows(at)
	}
	day := func(d, h, m int) time.Time { return time.Date(2026, 11, d, h, m, 0, 0, time.Local) }
	tick(day(2, 10, 0))
	tick(day(2, 11, 0)) // one-off ends: logged and removed
	b, _ := os.ReadFile(stateFile)
	if strings.Contains(string(b), "a.lan") {
		t.Fatalf("finished one-off window not removed: %s", b)
	}
	tick(day(3, 2, 0))
	tick(day(3, 3, 0))
	tick(day(4, 2, 0))
	tick(day(4, 2, 30)) // same occurrence: no second "started"
	tick(day(4, 3, 0))
	b, _ = os.ReadFile(stateFile)
	if !strings.Contains(string(b), "|daily") {
		t.Fatalf("repeating window must stay: %s", b)
	}
	if n := strings.Count(buf.String(), "schedule started for b.lan"); n != 2 {
		t.Fatalf("want 2 daily starts, got %d:\n%s", n, buf.String())
	}
	if n := strings.Count(buf.String(), "schedule ended for b.lan"); n != 2 {
		t.Fatalf("want 2 daily ends, got %d", n)
	}

	// a one-off that ended while nothing was watching is still removed, with a note
	b, _ = os.ReadFile(stateFile)
	gone := entry{mode: "on", sMode: "block", from: day(5, 1, 0), to: day(5, 2, 0)}
	b = []byte(strings.Replace(string(b), "{", `{"c.lan":"`+gone.String()+`",`, 1))
	if err := os.WriteFile(stateFile, b, 0o644); err != nil {
		t.Fatal(err)
	}
	tick(day(6, 9, 0))
	if !strings.Contains(buf.String(), "schedule for c.lan (block from Thu 05 Nov 01:00") || !strings.Contains(buf.String(), "had already ended; removed") {
		t.Fatalf("missing removal note:\n%s", buf.String())
	}

	// history page, newest first
	rec := httptest.NewRecorder()
	admin.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://ks.lan/?view=history", nil))
	page := rec.Body.String()
	first := strings.Index(page, "schedule created for a.lan: block from Mon 02 Nov 10:00")
	last := strings.Index(page, "schedule for c.lan")
	if first < 0 || last < 0 || last > first || !strings.Contains(page, "by bob") {
		t.Fatalf("history page wrong (created idx %d, removal idx %d)", first, last)
	}
	// admin page shows the next daily run and never an ended one-off
	rec = httptest.NewRecorder()
	admin.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://ks.lan/", nil))
	if !strings.Contains(rec.Body.String(), "every day 02:00–03:00</b> (next Sat 07 Nov 02:00)") {
		t.Fatal("admin page doesn't show next daily run")
	}
}

func TestHistoryTrim(t *testing.T) {
	_, admin, stateFile := newPair(t)
	k := admin.(*KillSwitch)
	infoLog = log.New(io.Discard, "", 0)
	defer func() { infoLog = log.New(os.Stdout, "", 0) }()
	for i := 0; i < historyMax+300; i++ {
		k.record("entry %d %s", i, strings.Repeat("x", 200))
	}
	lines := readHistory(stateFile+".history", 10*historyMax)
	if len(lines) > historyMax+300 || len(lines) < historyMax || !strings.Contains(lines[0], fmt.Sprintf("entry %d ", historyMax+299)) {
		t.Fatalf("got %d lines, newest %q", len(lines), lines[0][:40])
	}
}

func TestActorPrefersBasicAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://ks.lan/", nil)
	req.SetBasicAuth("alice", "pw")
	req.Header.Set("X-Authentik-Username", "mallory")
	req.Header.Set("X-Real-Ip", "192.0.2.9")
	if user, ip := actor(req); user != "alice" || ip != "192.0.2.9" {
		t.Fatalf("got %q %q, want basic-auth user alice", user, ip)
	}
	req = httptest.NewRequest(http.MethodPost, "http://ks.lan/", nil)
	req.Header.Set("X-Authentik-Username", "bob|x")
	if user, _ := actor(req); user != "bobx" {
		t.Fatalf("SSO user: got %q, want bobx (pipe stripped)", user)
	}
}

func TestFillBack(t *testing.T) {
	end := time.Date(2026, 11, 1, 4, 0, 0, 0, time.Local)
	for _, c := range []struct {
		page  string
		until time.Time
		want  string
	}{
		{"Expected back: {{back|soon}}", time.Time{}, "Expected back: soon"},
		{"Expected back: {{back}}", time.Time{}, "Expected back: soon"},
		{"Zurück: {{back|bald}}", time.Time{}, "Zurück: bald"},
		{"Expected back: {{back|soon}}", end, "Expected back: " + end.Format(timeFmt+" MST")},
		{"{{back}} / {{back|x}}", end, end.Format(timeFmt+" MST") + " / " + end.Format(timeFmt+" MST")},
		{"no placeholder {{other}}", end, "no placeholder {{other}}"},
	} {
		if got := string(fillBack([]byte(c.page), c.until)); got != c.want {
			t.Errorf("%q until=%v: got %q, want %q", c.page, !c.until.IsZero(), got, c.want)
		}
	}
}

func TestMaintPageShowsWindowEnd(t *testing.T) {
	dir := t.TempDir()
	page := filepath.Join(dir, "maintenance.html")
	if err := os.WriteFile(page, []byte("back: {{back|soon}}"), 0o644); err != nil {
		t.Fatal(err)
	}
	stateFile := filepath.Join(dir, "state.json")
	end := time.Now().Add(time.Hour).Truncate(time.Second)
	e := entry{mode: "on", sMode: "maint", from: time.Now().Add(-time.Minute).Truncate(time.Second), to: end}
	if err := os.WriteFile(stateFile, []byte(`{"w.lan":"`+e.String()+`","m.lan":"maint"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	gate, err := New(context.Background(), nil, &Config{StateFile: stateFile, MaintenanceFile: page}, "gate-back")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		seenMu.Lock()
		delete(excludedBy, "gate-back")
		delete(maintFiles, "gate-back")
		seenMu.Unlock()
	}()
	get := func(host string) string {
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil))
		return rec.Body.String()
	}
	if b := get("w.lan"); b != "back: "+end.Format(timeFmt+" MST") {
		t.Fatalf("scheduled window: got %q", b)
	}
	if b := get("m.lan"); b != "back: soon" {
		t.Fatalf("manual maint: got %q", b)
	}
}

func TestAdminFavicon(t *testing.T) {
	_, admin, _ := newPair(t)
	for _, path := range []string{"/", "/?view=history"} {
		rec := httptest.NewRecorder()
		admin.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://ks.lan"+path, nil))
		if !strings.Contains(rec.Body.String(), `<link rel="icon" href="data:image/svg+xml,`) {
			t.Fatalf("%s: no favicon", path)
		}
	}
}
