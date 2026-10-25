// Package traefik_killswitch is a Traefik middleware plugin: a per-host kill switch.
// It passes traffic through until a host (or every host) is switched to maintenance or block
// from the admin page. State lives in one JSON file shared by every middleware instance.
package traefik_killswitch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	modeOn    = "on"
	modeMaint = "maint"
	modeBlock = "block"
	allHosts  = "*"
)

const defaultMaintPage = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Maintenance</title><body style="font-family:sans-serif;text-align:center;padding-top:15vh">
<h1>Under maintenance</h1><p>This site is temporarily unavailable. Please try again later.</p></body>`

// Config is the plugin configuration.
type Config struct {
	StateFile       string   `json:"stateFile,omitempty"`
	Admin           bool     `json:"admin,omitempty"`
	MaintenanceFile string   `json:"maintenanceFile,omitempty"`
	ExcludeHosts    []string `json:"excludeHosts,omitempty"`
	// APIURL (admin only) is Traefik's API, e.g. http://127.0.0.1:8080. With it the admin page knows
	// which hosts have a router and whether that router uses the kill switch.
	APIURL string `json:"apiURL,omitempty"`
}

// CreateConfig returns the default configuration.
func CreateConfig() *Config {
	return &Config{StateFile: "/data/killswitch.json"}
}

// ponytail: package-level, shared by all instances in Traefik's interpreter; lost on restart.
var (
	seenMu sync.Mutex // guards seen and excludedBy
	seen   = map[string]bool{}
	// excludedBy holds each gate middleware's excludeHosts, keyed by middleware name, so the admin
	// page (a separate instance with its own config) can show which hosts are never switched off.
	excludedBy = map[string][]string{}
	// maintFiles holds each gate middleware's maintenanceFile; the other *.html files in its
	// directory are the templates the admin page offers per host.
	maintFiles = map[string]string{}
)

// KillSwitch is the middleware.
type KillSwitch struct {
	next      http.Handler
	name      string
	stateFile string
	admin     bool
	maintFile string
	exclude   map[string]bool
	apiURL    string

	routesMu  sync.Mutex
	routes    map[string]route
	routesErr error
	routesAt  time.Time

	mu      sync.Mutex
	state   map[string]string
	modTime time.Time
	size    int64
	checked time.Time
}

// New creates the middleware.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.StateFile == "" {
		return nil, fmt.Errorf("stateFile must be set")
	}
	exclude := map[string]bool{}
	list := []string{}
	for _, h := range config.ExcludeHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		exclude[h] = true
		list = append(list, h)
	}
	k := &KillSwitch{next: next, name: name, stateFile: config.StateFile, admin: config.Admin, maintFile: config.MaintenanceFile,
		exclude: exclude, apiURL: strings.TrimRight(config.APIURL, "/")}
	seenMu.Lock()
	if !config.Admin {
		excludedBy[name] = list
		maintFiles[name] = config.MaintenanceFile
	}
	watched[config.StateFile] = k
	seenMu.Unlock()
	watchOnce.Do(func() { go watch() })
	return k, nil
}

func (k *KillSwitch) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if k.admin {
		k.serveAdmin(rw, req)
		return
	}
	host := hostOnly(req.Host)
	// Excluded hosts (the admin page, the auth provider) are never gated, so "*" can't lock you out.
	if k.exclude[host] {
		k.next.ServeHTTP(rw, req)
		return
	}
	seenMu.Lock()
	seen[host] = true
	seenMu.Unlock()

	mode, tpl, until := k.modeFor(host)
	switch mode {
	case modeMaint:
		retry := 300
		if !until.IsZero() {
			retry = int(time.Until(until).Seconds()) + 1
		}
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.Header().Set("Cache-Control", "no-store")
		rw.Header().Set("Retry-After", strconv.Itoa(retry))
		rw.WriteHeader(http.StatusServiceUnavailable)
		_, _ = rw.Write(k.maintPage(tpl))
	case modeBlock:
		http.Error(rw, "Forbidden", http.StatusForbidden)
	default:
		k.next.ServeHTTP(rw, req)
	}
}

// maintPage reads maintenanceFile on every maintenance response, so edits apply without a restart.
// A missing or unreadable file falls back to the built-in page: it must never break the middleware.
// tpl names another *.html file next to maintenanceFile; unknown or unreadable falls back to maintenanceFile.
func (k *KillSwitch) maintPage(tpl string) []byte {
	if tpl != "" && k.maintFile != "" && validTemplate(tpl) {
		b, err := os.ReadFile(filepath.Join(filepath.Dir(k.maintFile), tpl+".html"))
		if err == nil {
			return b
		}
		log.Printf("killswitch %s: template %s: %v (serving default page)", k.name, tpl, err)
	}
	if k.maintFile != "" {
		b, err := os.ReadFile(k.maintFile)
		if err == nil {
			return b
		}
		log.Printf("killswitch %s: %v (serving built-in page)", k.name, err)
	}
	return []byte(defaultMaintPage)
}

// modeFor returns the effective mode, template and, inside a scheduled window, its end.
// A non-"on" global switch wins over the per-host one.
func (k *KillSwitch) modeFor(host string) (string, string, time.Time) {
	state := k.load()
	t := now()
	if m, tpl, until := parseEntry(state[allHosts]).effective(t); m != modeOn {
		return m, tpl, until
	}
	return parseEntry(state[host]).effective(t)
}

// now is the clock; tests replace it.
var now = time.Now

// infoLog writes Traefik-style INFO lines to stdout. Traefik tags the standard logger's output as ERR,
// so actions are logged here instead; errors still go through log.Printf.
var infoLog = log.New(os.Stdout, "", 0)

func logInfo(format string, args ...interface{}) {
	infoLog.Printf("%s INF KILL-SWITCH: %s", time.Now().Format(time.RFC3339), fmt.Sprintf(format, args...))
}

// watched holds one instance per state file; watch() logs scheduled windows starting and ending.
var (
	watched     = map[string]*KillSwitch{}
	watchOnce   sync.Once
	announcedMu sync.Mutex
	announced   = map[string]string{} // window key -> "started" or "ended"
)

// ponytail: one 1s ticker for the whole process, never stopped; fine for a plugin that lives as long as Traefik.
func watch() {
	for range time.Tick(time.Second) {
		seenMu.Lock()
		list := []*KillSwitch{}
		for _, k := range watched {
			list = append(list, k)
		}
		seenMu.Unlock()
		for _, k := range list {
			k.checkWindows(time.Now())
		}
	}
}

// checkWindows logs each window's start and end once. A window first seen already running
// (e.g. after a Traefik restart) is logged as "active" instead of "started".
func (k *KillSwitch) checkWindows(t time.Time) {
	announcedMu.Lock()
	defer announcedMu.Unlock()
	for host, v := range k.load() {
		e := parseEntry(v)
		if !e.scheduled() {
			continue
		}
		key := k.stateFile + "|" + host + "|" + e.from.Format(time.RFC3339) + "|" + e.to.Format(time.RFC3339)
		switch {
		case e.active(t) && announced[key] == "":
			verb := "started"
			if t.Sub(e.from) > 5*time.Second {
				verb = "active since " + e.from.In(time.Local).Format(timeFmt)
			}
			logInfo("schedule %s for %s: %s until %s%s", verb, hostLabel(host), modeLabel(e.sMode, e.sTpl),
				e.to.In(time.Local).Format(timeFmt+" MST"), e.createdLabel())
			announced[key] = "started"
		case !t.Before(e.to) && announced[key] == "started":
			logInfo("schedule ended for %s: back to %s", hostLabel(host), modeLabel(e.mode, e.tpl))
			announced[key] = "ended"
		}
	}
}

func hostLabel(host string) string {
	if host == allHosts {
		return "all sites"
	}
	return host
}

func modeLabel(mode, tpl string) string {
	if tpl != "" {
		return mode + " (page " + tpl + ")"
	}
	return mode
}

func (e entry) createdLabel() string {
	if e.created.IsZero() {
		return ""
	}
	l := " (created " + e.created.In(time.Local).Format(timeFmt)
	if e.by != "" {
		l += " by " + e.by
	}
	return l + ")"
}

// actor names who made an admin change, for the log: the SSO or basic-auth user, and the client IP.
func actor(req *http.Request) (string, string) {
	user := req.Header.Get("X-Authentik-Username")
	if user == "" {
		if u, _, ok := req.BasicAuth(); ok {
			user = u
		}
	}
	// Keep it a plain token: it's stored in the state value and written to logs.
	user = strings.Map(func(r rune) rune {
		if r == '|' || r == '"' || r == '\\' || r < ' ' {
			return -1
		}
		return r
	}, user)
	ip := req.Header.Get("X-Real-Ip")
	if ip == "" {
		ip = req.RemoteAddr
		if h, _, err := net.SplitHostPort(ip); err == nil {
			ip = h
		}
	}
	return user, ip
}

// entry is one state value: the normal mode, plus an optional scheduled window with its own mode.
// Stored as "maint:downtime" or, with a window, "on|block|<from RFC3339>|<to RFC3339>".
type entry struct {
	mode, tpl   string
	sMode, sTpl string
	from, to    time.Time
	created     time.Time // when the window was planned, and by whom (optional)
	by          string
}

func parseEntry(v string) entry {
	parts := strings.Split(v, "|")
	var e entry
	// Separate statements on purpose: Yaegi mishandles tuple assignment to struct fields.
	mode, tpl := splitMode(parts[0])
	e.mode = mode
	e.tpl = tpl
	if len(parts) >= 4 {
		from, err1 := time.Parse(time.RFC3339, parts[2])
		to, err2 := time.Parse(time.RFC3339, parts[3])
		if err1 == nil && err2 == nil {
			sMode, sTpl := splitMode(parts[1])
			e.sMode = sMode
			e.sTpl = sTpl
			e.from = from
			e.to = to
		}
		if len(parts) == 6 {
			created, err := time.Parse(time.RFC3339, parts[4])
			if err == nil {
				e.created = created
			}
			e.by = parts[5]
		}
	}
	return e
}

func (e entry) String() string {
	v := joinMode(e.mode, e.tpl)
	if e.scheduled() {
		v += "|" + joinMode(e.sMode, e.sTpl) + "|" + e.from.Format(time.RFC3339) + "|" + e.to.Format(time.RFC3339)
		if !e.created.IsZero() {
			v += "|" + e.created.Format(time.RFC3339) + "|" + e.by
		}
	}
	return v
}

func (e entry) scheduled() bool { return !e.to.IsZero() }

func (e entry) active(t time.Time) bool {
	return e.scheduled() && !t.Before(e.from) && t.Before(e.to)
}

// effective returns the mode and template in force at t, and the window's end while one is active.
func (e entry) effective(t time.Time) (string, string, time.Time) {
	if e.active(t) {
		return e.sMode, e.sTpl, e.to
	}
	return e.mode, e.tpl, time.Time{}
}

func joinMode(mode, tpl string) string {
	if tpl != "" {
		return mode + ":" + tpl
	}
	return mode
}

// splitMode parses a state value: "maint", or "maint:downtime" to pick a template. Empty means "on".
func splitMode(v string) (string, string) {
	parts := strings.SplitN(v, ":", 2)
	mode := parts[0]
	if mode == "" {
		mode = modeOn
	}
	if len(parts) == 2 {
		return mode, parts[1]
	}
	return mode, ""
}

// validTemplate allows plain file names only, so a template can't point outside its directory.
func validTemplate(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// templates lists the selectable templates (file names without .html) next to every gate's maintenanceFile,
// leaving out the maintenanceFile itself, which is the default.
func templates() []string {
	seenMu.Lock()
	files := []string{}
	for _, f := range maintFiles {
		if f != "" {
			files = append(files, f)
		}
	}
	seenMu.Unlock()
	set := map[string]bool{}
	for _, f := range files {
		entries, err := os.ReadDir(filepath.Dir(f))
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := strings.TrimSuffix(e.Name(), ".html")
			if !e.IsDir() && name != e.Name() && e.Name() != filepath.Base(f) && validTemplate(name) {
				set[name] = true
			}
		}
	}
	list := []string{}
	for t := range set {
		list = append(list, t)
	}
	sort.Strings(list)
	return list
}

// load returns the cached state, re-reading the file when its mtime changes (checked at most once a second).
func (k *KillSwitch) load() map[string]string {
	k.mu.Lock()
	defer k.mu.Unlock()
	if time.Since(k.checked) < time.Second && k.state != nil {
		return k.state
	}
	k.checked = time.Now()
	if k.state == nil {
		k.state = map[string]string{}
	}
	fi, err := os.Stat(k.stateFile)
	if errors.Is(err, fs.ErrNotExist) {
		k.state = map[string]string{} // no file = everything on
		k.modTime = time.Time{}
		k.size = 0
		return k.state
	}
	if err == nil && fi.ModTime().Equal(k.modTime) && fi.Size() == k.size {
		return k.state
	}
	state, err := readState(k.stateFile)
	if err != nil {
		// Fail safe: a corrupt or unreadable file keeps the last good state rather than reopening blocked sites.
		log.Printf("killswitch %s: %v (keeping last state)", k.name, err)
		return k.state
	}
	// Separate statements on purpose: Yaegi mishandles tuple assignment to struct fields.
	k.state = state
	k.modTime = fi.ModTime()
	k.size = fi.Size()
	return k.state
}

func readState(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	state := map[string]string{}
	if len(strings.TrimSpace(string(b))) == 0 {
		return state, nil
	}
	if err := json.Unmarshal(b, &state); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return state, nil
}

// writeMu serializes read-modify-write of the state file across admin instances.
var writeMu sync.Mutex

// update applies fn to host's entry and saves the state file, dropping windows that have ended.
func (k *KillSwitch) update(host string, fn func(e *entry)) error {
	writeMu.Lock()
	defer writeMu.Unlock()
	state, err := readState(k.stateFile)
	// Not `state, err = map..., nil`: Yaegi (Traefik's interpreter) does not reset err in that tuple assignment.
	if errors.Is(err, fs.ErrNotExist) {
		state = map[string]string{}
	} else if err != nil {
		return err
	}
	e := parseEntry(state[host])
	fn(&e)
	if e.scheduled() && !now().Before(e.to) {
		e.to = time.Time{}
	}
	if v := e.String(); v == modeOn && host != allHosts {
		delete(state, host)
	} else {
		state[host] = v
	}
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := k.stateFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, k.stateFile); err != nil {
		return err
	}
	k.mu.Lock()
	k.checked = time.Time{} // force reload on next request
	k.mu.Unlock()
	return nil
}

// route is what Traefik's API says about one host: the routers serving it and which of them skip the kill switch.
type route struct {
	routers     []string
	unprotected []string
}

func (r route) protected() bool { return len(r.unprotected) == 0 }

type apiRouter struct {
	Name        string   `json:"name"`
	Rule        string   `json:"rule"`
	Status      string   `json:"status"`
	Middlewares []string `json:"middlewares"`
}

type apiMiddleware struct {
	Name  string `json:"name"`
	Chain *struct {
		Middlewares []string `json:"middlewares"`
	} `json:"chain"`
}

// hostRoutes returns host -> route from Traefik's API, cached for 10s. Without apiURL it returns nil, nil.
func (k *KillSwitch) hostRoutes() (map[string]route, error) {
	if k.apiURL == "" {
		return nil, nil
	}
	k.routesMu.Lock()
	defer k.routesMu.Unlock()
	if time.Since(k.routesAt) < 10*time.Second {
		return k.routes, k.routesErr
	}
	routes, err := fetchRoutes(k.apiURL)
	k.routes = routes
	k.routesErr = err
	k.routesAt = time.Now()
	if err != nil {
		log.Printf("killswitch %s: reading Traefik API: %v", k.name, err)
	}
	return routes, err
}

var apiClient = &http.Client{Timeout: 3 * time.Second}

// apiGet reads every page of a Traefik API list endpoint into out.
func apiGet(base, path string, out func([]byte) error) error {
	for page := 1; page < 100; page++ {
		resp, err := apiClient.Get(base + path + "?per_page=500&page=" + strconv.Itoa(page))
		if err != nil {
			return err
		}
		b, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s: %s", path, resp.Status)
		}
		if err := out(b); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		next := resp.Header.Get("X-Next-Page")
		if next == "" || next == "1" {
			return nil
		}
	}
	return nil
}

func fetchRoutes(base string) (map[string]route, error) {
	var routers []apiRouter
	err := apiGet(base, "/api/http/routers", func(b []byte) error {
		var page []apiRouter
		if err := json.Unmarshal(b, &page); err != nil {
			return err
		}
		routers = append(routers, page...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	chains := map[string][]string{}
	err = apiGet(base, "/api/http/middlewares", func(b []byte) error {
		var page []apiMiddleware
		if err := json.Unmarshal(b, &page); err != nil {
			return err
		}
		for _, m := range page {
			if m.Chain != nil {
				chains[m.Name] = m.Chain.Middlewares
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	seenMu.Lock()
	gates := map[string]bool{}
	for name := range excludedBy {
		gates[name] = true
	}
	seenMu.Unlock()

	routes := map[string]route{}
	for _, r := range routers {
		if r.Status != "enabled" {
			continue
		}
		gated := false
		for _, m := range r.Middlewares {
			if usesGate(m, chains, gates, 0) {
				gated = true
			}
		}
		for _, h := range hostsFromRule(r.Rule) {
			rt := routes[h]
			rt.routers = append(rt.routers, r.Name)
			if !gated {
				rt.unprotected = append(rt.unprotected, r.Name)
			}
			routes[h] = rt
		}
	}
	return routes, nil
}

// usesGate reports whether middleware name is a kill switch gate, directly or inside a chain.
func usesGate(name string, chains map[string][]string, gates map[string]bool, depth int) bool {
	if gates[name] {
		return true
	}
	if depth > 5 {
		return false
	}
	provider := ""
	if i := strings.LastIndex(name, "@"); i >= 0 {
		provider = name[i:]
	}
	for _, m := range chains[name] {
		if !strings.Contains(m, "@") {
			m += provider // chain members are relative to the chain's provider
		}
		if usesGate(m, chains, gates, depth+1) {
			return true
		}
	}
	return false
}

// hostsFromRule extracts the names in Host(`a`) / Host(`a`, `b`) matchers; HostRegexp and HostSNI are skipped.
func hostsFromRule(rule string) []string {
	hosts := []string{}
	for i := 0; i < len(rule); i++ {
		if !strings.HasPrefix(rule[i:], "Host(") || (i > 0 && isIdent(rule[i-1])) {
			continue
		}
		end := strings.Index(rule[i:], ")")
		if end < 0 {
			break
		}
		args := rule[i+5 : i+end]
		for _, q := range []string{"`", `"`} {
			parts := strings.Split(args, q)
			for j := 1; j < len(parts); j += 2 {
				hosts = append(hosts, strings.ToLower(parts[j]))
			}
		}
		i += end
	}
	return hosts
}

func isIdent(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// checkHost decides whether host may be switched to mode. It returns an error to refuse,
// or a warning to show while still saving. Switching on and cancelling are always allowed.
func (k *KillSwitch) checkHost(host, mode, action string) (string, string) {
	if host == allHosts || action == "unschedule" || (action == "" && mode == modeOn) {
		return "", ""
	}
	routes, err := k.hostRoutes()
	if routes != nil && err == nil {
		r, ok := routes[host]
		if !ok {
			return "No Traefik router serves " + host + ", so switching it would do nothing. Check the spelling.", ""
		}
		if !r.protected() {
			return host + " is served by " + strings.Join(r.unprotected, ", ") +
				", which doesn't use the kill switch. Add the kill switch middleware to that router first.", ""
		}
		return "", ""
	}
	seenMu.Lock()
	ok := seen[host]
	seenMu.Unlock()
	if !ok {
		return "", "Saved, but no request for " + host + " has passed the kill switch since Traefik started. " +
			"If its router doesn't use the kill switch middleware, this setting has no effect."
	}
	return "", ""
}

func (k *KillSwitch) serveAdmin(rw http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet, http.MethodHead:
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.Header().Set("Cache-Control", "no-store")
		_, _ = rw.Write([]byte(k.renderAdmin(req.URL.Query().Get("err"), req.URL.Query().Get("warn"))))
	case http.MethodPost:
		if !sameOrigin(req) {
			http.Error(rw, "cross-origin request refused", http.StatusForbidden)
			return
		}
		if err := req.ParseForm(); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		host := strings.ToLower(strings.TrimSpace(req.PostForm.Get("host")))
		mode := req.PostForm.Get("mode")
		action := req.PostForm.Get("action")
		if host == "" || (action != "unschedule" && mode != modeOn && mode != modeMaint && mode != modeBlock) {
			http.Error(rw, "invalid host or mode", http.StatusBadRequest)
			return
		}
		fail := func(msg string) {
			http.Redirect(rw, req, req.URL.Path+"?err="+url.QueryEscape(msg), http.StatusSeeOther)
		}
		tpl := req.PostForm.Get("template")
		if tpl != "" && !contains(templates(), tpl) {
			fail("unknown template " + tpl)
			return
		}
		if excludedHosts()[host] {
			fail(host + " is in excludeHosts and is never switched off")
			return
		}
		refuse, warn := k.checkHost(host, mode, action)
		if refuse != "" {
			fail(refuse)
			return
		}
		user, ip := actor(req)
		who := " from " + ip
		if user != "" {
			who = " by " + user + who
		}
		var fn func(e *entry)
		var msg string
		switch action {
		case "schedule":
			from, err1 := time.ParseInLocation("2006-01-02T15:04", req.PostForm.Get("from"), time.Local)
			to, err2 := time.ParseInLocation("2006-01-02T15:04", req.PostForm.Get("to"), time.Local)
			switch {
			case err1 != nil || err2 != nil:
				fail("enter both a start and an end date and time")
				return
			case mode == modeOn:
				fail("a schedule must switch to maint or block")
				return
			case !to.After(from):
				fail("the end must be after the start")
				return
			case !to.After(now()):
				fail("the end is in the past")
				return
			}
			created := now()
			fn = func(e *entry) {
				e.sMode = mode
				e.sTpl = tpl
				e.from = from
				e.to = to
				e.created = created
				e.by = user
			}
			msg = "schedule created for " + hostLabel(host) + ": " + modeLabel(mode, tpl) + " from " +
				from.Format(timeFmt) + " to " + to.Format(timeFmt+" MST") + who
		case "unschedule":
			fn = func(e *entry) { e.to = time.Time{} }
			msg = "schedule cancelled for " + hostLabel(host) + who
		default:
			fn = func(e *entry) {
				e.mode = mode
				e.tpl = tpl
			}
			msg = hostLabel(host) + " set to " + modeLabel(mode, tpl) + who
		}
		if err := k.update(host, fn); err != nil {
			log.Printf("killswitch %s: saving state: %v", k.name, err)
			fail("Save failed: " + err.Error())
			return
		}
		logInfo("%s", msg)
		target := req.URL.Path
		if warn != "" {
			target += "?warn=" + url.QueryEscape(warn)
		}
		http.Redirect(rw, req, target, http.StatusSeeOther)
	default:
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// sameOrigin rejects cross-site form posts (CSRF): browsers send Origin on POST.
func sameOrigin(req *http.Request) bool {
	if site := req.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	origin := req.Header.Get("Origin")
	if origin == "" {
		return true // non-browser client (curl); auth in front of the admin router is the real gate
	}
	u, err := url.Parse(origin)
	return err == nil && strings.EqualFold(u.Host, req.Host)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// excludedHosts returns the union of every gate middleware's excludeHosts.
func excludedHosts() map[string]bool {
	seenMu.Lock()
	defer seenMu.Unlock()
	all := map[string]bool{}
	for _, list := range excludedBy {
		for _, h := range list {
			all[h] = true
		}
	}
	return all
}

const adminStyle = `<style>
:root{color-scheme:light dark;--bg:#f5f6f8;--card:#fff;--text:#1d2330;--muted:#5d6675;--border:#e1e4e9;
--on:#1a7f37;--maint:#b35900;--block:#c62828;--btn:#eef0f3;--btn-text:#1d2330;--err:#fde7e7}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--card:#1d2128;--text:#e8eaee;--muted:#9aa3b0;--border:#2c323b;
--on:#3fb950;--maint:#f0a04b;--block:#ff6b6b;--btn:#2a3039;--btn-text:#e8eaee;--err:#4a1f22}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:52rem;margin:0 auto;padding:1.5rem 16px 3rem}
h1{font-size:1.5rem;margin:0 0 .25rem}h2{font-size:1.05rem;margin:2rem 0 .5rem}
p{color:var(--muted);margin:.25rem 0 1rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;overflow:hidden}
.row{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem 1rem;padding:.7rem 1rem;border-top:1px solid var(--border)}
.row:first-child{border-top:0}.row.all{background:color-mix(in srgb,var(--text) 4%,transparent)}
.host{flex:1 1 14rem;font-weight:600;overflow-wrap:anywhere}.host small{display:block;font-weight:400;color:var(--muted)}
.pill{font-size:.8rem;font-weight:700;text-transform:uppercase;letter-spacing:.03em;padding:.15rem .6rem;border-radius:999px;
color:var(--c);background:color-mix(in srgb,var(--c) 14%,transparent)}
.on{--c:var(--on)}.maint{--c:var(--maint)}.block{--c:var(--block)}
form{display:flex;gap:.35rem;margin:0}
button{font:inherit;padding:.3rem .8rem;border-radius:8px;border:1px solid var(--border);background:var(--btn);color:var(--btn-text);cursor:pointer}
button:hover:not([disabled]){border-color:var(--c)}
button.active{color:#fff;background:var(--c);border-color:var(--c)}
select{font:inherit;padding:.3rem .5rem;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text)}
input{font:inherit;padding:.3rem .6rem;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);flex:1 1 14rem}
.err{background:var(--err);border-radius:8px;padding:.6rem 1rem;color:var(--text)}
.warn{background:color-mix(in srgb,var(--maint) 16%,transparent);border-radius:8px;padding:.6rem 1rem;color:var(--text)}
.host small.bad{color:var(--block)}
details.np summary h2{display:inline;font-size:1.05rem}details.np{margin-top:2rem}
ul.excl{margin:0;padding:.6rem 1rem .6rem 2rem;color:var(--muted)}
.sched{flex-basis:100%;display:flex;flex-wrap:wrap;align-items:center;gap:.35rem .75rem;font-size:.9rem;color:var(--muted)}
.sched b{color:var(--text)}details{flex-basis:100%}summary{cursor:pointer;color:var(--muted);font-size:.9rem}
details form{flex-wrap:wrap;align-items:center;margin-top:.5rem}details label{display:flex;gap:.35rem;align-items:center}
details input{flex:0 1 auto}
</style>`

// modeButtons renders the per-host form; with templates, a select picks the page "maint" will show.
func modeButtons(host, cur, curTpl string, tpls []string) string {
	var b strings.Builder
	b.WriteString(`<form method="post"><input type="hidden" name="host" value="` + html.EscapeString(host) + `">`)
	b.WriteString(templateSelect(tpls, curTpl))
	for _, m := range []string{modeOn, modeMaint, modeBlock} {
		active := ""
		if m == cur {
			active = " active"
		}
		b.WriteString(`<button class="` + m + active + `" name="mode" value="` + m + `">` + m + `</button>`)
	}
	b.WriteString(`</form>`)
	return b.String()
}

func templateSelect(tpls []string, cur string) string {
	if len(tpls) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<select name="template" aria-label="Maintenance page"><option value="">default page</option>`)
	for _, t := range tpls {
		sel := ""
		if t == cur {
			sel = " selected"
		}
		b.WriteString(`<option value="` + html.EscapeString(t) + `"` + sel + `>` + html.EscapeString(t) + `</option>`)
	}
	b.WriteString(`</select>`)
	return b.String()
}

const timeFmt = "Mon 02 Jan 15:04"

// scheduleHTML shows a host's window with a Cancel button, and a form to plan a new one.
func scheduleHTML(host string, e entry, tpls []string) string {
	var b strings.Builder
	eh := html.EscapeString(host)
	t := now()
	if e.scheduled() {
		state := "upcoming"
		if e.active(t) {
			state = "active"
		}
		label := e.sMode
		if e.sTpl != "" {
			label += " · " + e.sTpl
		}
		b.WriteString(`<div class="sched">Scheduled <span class="pill ` + e.sMode + `">` + html.EscapeString(label) + `</span> <b>` +
			e.from.In(time.Local).Format(timeFmt) + ` → ` + e.to.In(time.Local).Format(timeFmt) + `</b> (` + state + `)` + html.EscapeString(e.createdLabel()) +
			`<form method="post"><input type="hidden" name="host" value="` + eh + `"><button name="action" value="unschedule">Cancel</button></form></div>`)
	}
	b.WriteString(`<details><summary>Schedule…</summary><form method="post"><input type="hidden" name="host" value="` + eh + `">` +
		`<input type="hidden" name="action" value="schedule"><select name="mode" aria-label="Scheduled mode"><option value="maint">maint</option><option value="block">block</option></select>` +
		templateSelect(tpls, "") +
		`<label>from <input type="datetime-local" name="from" required></label><label>to <input type="datetime-local" name="to" required></label>` +
		`<button>Schedule</button></form></details>`)
	return b.String()
}

func (k *KillSwitch) renderAdmin(errMsg, warnMsg string) string {
	state := k.load()
	excluded := excludedHosts()
	routes, apiErr := k.hostRoutes()
	hosts := map[string]bool{}
	for h := range state {
		hosts[h] = true
	}
	unprotected := []string{}
	for h, r := range routes {
		if excluded[h] {
			continue
		}
		if r.protected() {
			hosts[h] = true
		} else if !hosts[h] {
			unprotected = append(unprotected, h)
		}
	}
	sort.Strings(unprotected)
	seenMu.Lock()
	for h := range seen {
		hosts[h] = true
	}
	seenMu.Unlock()
	delete(hosts, allHosts)
	list := []string{}
	for h := range hosts {
		if !excluded[h] {
			list = append(list, h)
		}
	}
	sort.Strings(list)
	exList := []string{}
	for h := range excluded {
		exList = append(exList, h)
	}
	sort.Strings(exList)

	tpls := templates()
	t := now()
	pill := func(m, tpl string) string {
		label := m
		if m == modeMaint && tpl != "" {
			label += " · " + html.EscapeString(tpl)
		}
		return `<span class="pill ` + m + `">` + label + `</span>`
	}

	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kill switch</title>` + adminStyle + `<main><h1>Kill switch</h1>
<p><b>on</b> serves the site, <b>maint</b> shows the maintenance page (503), <b>block</b> refuses every request (403).</p>`)
	if len(tpls) > 0 {
		b.WriteString(`<p>Pick a page in the list, then click <b>maint</b>. Clicking <b>maint</b> again switches a site to the newly picked page.</p>`)
	}
	b.WriteString(`<p>Schedules use server time (` + t.Format("MST") + `, now ` + t.Format(timeFmt) + `). A site switches back to its normal mode when its window ends.</p>`)
	if errMsg != "" {
		b.WriteString(`<p class="err">` + html.EscapeString(errMsg) + `</p>`)
	}
	if warnMsg != "" {
		b.WriteString(`<p class="warn">` + html.EscapeString(warnMsg) + `</p>`)
	}
	if apiErr != nil {
		b.WriteString(`<p class="warn">Traefik API unreachable (` + html.EscapeString(apiErr.Error()) + `): can't check which hosts are protected.</p>`)
	}
	ge := parseEntry(state[allHosts])
	g, gTpl, _ := ge.effective(t)
	b.WriteString(`<div class="card"><div class="row all"><div class="host">All sites<small>Overrides every per-site setting while not "on"`)
	if len(exList) > 0 {
		b.WriteString(`, except the always-on hosts below`)
	}
	b.WriteString(`</small></div>` + pill(g, gTpl) + modeButtons(allHosts, ge.mode, ge.tpl, tpls) + scheduleHTML(allHosts, ge, tpls) + `</div>`)
	for _, h := range list {
		e := parseEntry(state[h])
		m, tpl, _ := e.effective(t)
		note := ""
		if routes != nil {
			if r, ok := routes[h]; !ok {
				note = `<small class="bad">no Traefik router: this setting does nothing</small>`
			} else if !r.protected() {
				note = `<small class="bad">not protected: ` + html.EscapeString(strings.Join(r.unprotected, ", ")) + ` doesn't use the kill switch</small>`
			}
		}
		b.WriteString(`<div class="row"><div class="host">` + html.EscapeString(h) + note + `</div>` + pill(m, tpl) + modeButtons(h, e.mode, e.tpl, tpls) + scheduleHTML(h, e, tpls) + `</div>`)
	}
	if len(list) == 0 {
		b.WriteString(`<div class="row"><p>No sites seen yet. They appear after their first request, or add one below.</p></div>`)
	}
	b.WriteString(`</div>`)
	if len(unprotected) > 0 {
		b.WriteString(`<details class="np"><summary><h2>Not protected (` + strconv.Itoa(len(unprotected)) + `)</h2></summary>` +
			`<p>These hosts have a Traefik router without the kill switch middleware, so they can't be switched off here.</p><div class="card"><ul class="excl">`)
		for _, h := range unprotected {
			b.WriteString(`<li>` + html.EscapeString(h) + ` <small>(` + html.EscapeString(strings.Join(routes[h].unprotected, ", ")) + `)</small></li>`)
		}
		b.WriteString(`</ul></div></details>`)
	}
	if len(exList) > 0 {
		b.WriteString(`<h2>Always on</h2><p>Listed in <code>excludeHosts</code>: never switched off, not even by "All sites".</p><div class="card"><ul class="excl">`)
		for _, h := range exList {
			b.WriteString(`<li>` + html.EscapeString(h) + `</li>`)
		}
		b.WriteString(`</ul></div>`)
	}
	b.WriteString(`<h2>Add site</h2><div class="card"><div class="row"><form method="post" style="flex:1;flex-wrap:wrap">` +
		`<input name="host" placeholder="app.example.com" required>` + templateSelect(tpls, "") + `<button class="maint" name="mode" value="maint">maint</button>` +
		`<button class="block" name="mode" value="block">block</button></form></div></div></main></html>`)
	return b.String()
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(hostport)
}
