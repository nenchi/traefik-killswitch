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
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
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
	StateFile       string `json:"stateFile,omitempty"`
	Admin           bool   `json:"admin,omitempty"`
	MaintenanceFile string `json:"maintenanceFile,omitempty"`
}

// CreateConfig returns the default configuration.
func CreateConfig() *Config {
	return &Config{StateFile: "/data/killswitch.json"}
}

// ponytail: package-level, shared by all instances in Traefik's interpreter; lost on restart.
var (
	seenMu sync.Mutex
	seen   = map[string]bool{}
)

// KillSwitch is the middleware.
type KillSwitch struct {
	next      http.Handler
	name      string
	stateFile string
	admin     bool
	maintPage []byte

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
	page := []byte(defaultMaintPage)
	if config.MaintenanceFile != "" {
		b, err := os.ReadFile(config.MaintenanceFile)
		if err != nil {
			return nil, fmt.Errorf("reading maintenanceFile: %w", err)
		}
		page = b
	}
	return &KillSwitch{next: next, name: name, stateFile: config.StateFile, admin: config.Admin, maintPage: page}, nil
}

func (k *KillSwitch) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if k.admin {
		k.serveAdmin(rw, req)
		return
	}
	host := hostOnly(req.Host)
	seenMu.Lock()
	seen[host] = true
	seenMu.Unlock()

	switch k.modeFor(host) {
	case modeMaint:
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.Header().Set("Cache-Control", "no-store")
		rw.Header().Set("Retry-After", "300")
		rw.WriteHeader(http.StatusServiceUnavailable)
		_, _ = rw.Write(k.maintPage)
	case modeBlock:
		http.Error(rw, "Forbidden", http.StatusForbidden)
	default:
		k.next.ServeHTTP(rw, req)
	}
}

// modeFor returns the effective mode: a non-"on" global switch wins over the per-host one.
func (k *KillSwitch) modeFor(host string) string {
	state := k.load()
	if m := state[allHosts]; m != "" && m != modeOn {
		return m
	}
	return state[host]
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

func (k *KillSwitch) setMode(host, mode string) error {
	writeMu.Lock()
	defer writeMu.Unlock()
	state, err := readState(k.stateFile)
	// Not `state, err = map..., nil`: Yaegi (Traefik's interpreter) does not reset err in that tuple assignment.
	if errors.Is(err, fs.ErrNotExist) {
		state = map[string]string{}
	} else if err != nil {
		return err
	}
	if mode == modeOn && host != allHosts {
		delete(state, host)
	} else {
		state[host] = mode
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

func (k *KillSwitch) serveAdmin(rw http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet, http.MethodHead:
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.Header().Set("Cache-Control", "no-store")
		_, _ = rw.Write([]byte(k.renderAdmin(req.URL.Query().Get("err"))))
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
		if host == "" || (mode != modeOn && mode != modeMaint && mode != modeBlock) {
			http.Error(rw, "invalid host or mode", http.StatusBadRequest)
			return
		}
		target := req.URL.Path
		if err := k.setMode(host, mode); err != nil {
			log.Printf("killswitch %s: saving state: %v", k.name, err)
			target += "?err=" + url.QueryEscape(err.Error())
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

func (k *KillSwitch) renderAdmin(errMsg string) string {
	state := k.load()
	hosts := map[string]bool{}
	for h := range state {
		hosts[h] = true
	}
	seenMu.Lock()
	for h := range seen {
		hosts[h] = true
	}
	seenMu.Unlock()
	delete(hosts, allHosts)
	list := make([]string, 0, len(hosts))
	for h := range hosts {
		list = append(list, h)
	}
	sort.Strings(list)
	list = append([]string{allHosts}, list...)

	var b strings.Builder
	b.WriteString(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Kill switch</title><style>
body{font-family:system-ui,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem}
table{border-collapse:collapse;width:100%}td{padding:.5rem;border-bottom:1px solid #ccc}
button{padding:.35rem .8rem;margin-right:.25rem;cursor:pointer}button[disabled]{font-weight:bold}
.on{color:#080}.maint{color:#b60}.block{color:#c00}.err{background:#fdd;padding:.5rem}
</style><h1>Kill switch</h1>`)
	if errMsg != "" {
		b.WriteString(`<p class="err">Save failed: ` + html.EscapeString(errMsg) + `</p>`)
	}
	b.WriteString(`<p><b>*</b> switches every site and overrides the per-host setting.</p><table>`)
	for _, h := range list {
		cur := state[h]
		if cur == "" {
			cur = modeOn
		}
		eh := html.EscapeString(h)
		label := eh
		if h == allHosts {
			label = "* (all sites)"
		}
		b.WriteString(`<tr><td>` + label + `</td><td class="` + cur + `">` + cur + `</td><td><form method="post">` +
			`<input type="hidden" name="host" value="` + eh + `">`)
		for _, m := range []string{modeOn, modeMaint, modeBlock} {
			dis := ""
			if m == cur {
				dis = " disabled"
			}
			b.WriteString(`<button name="mode" value="` + m + `"` + dis + `>` + m + `</button>`)
		}
		b.WriteString(`</form></td></tr>`)
	}
	b.WriteString(`</table><h2>Add host</h2><form method="post"><input name="host" placeholder="app.example.com" required> ` +
		`<button name="mode" value="maint">maint</button><button name="mode" value="block">block</button></form>`)
	return b.String()
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(hostport)
}
