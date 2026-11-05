package traefik_killswitch

import (
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GeoConfig turns on the country allow-list for a gate middleware. The country comes from a header set by a
// trusted proxy (Cloudflare, CloudFront, a GeoIP-enabled nginx, ...) or from a local .mmdb file, or both.
// The allowed countries live in the state file and are edited on the admin page; Countries is only the
// starting list until the first save there.
type GeoConfig struct {
	CountryHeader  string   `json:"countryHeader,omitempty"`  // e.g. CF-IPCountry, CloudFront-Viewer-Country
	TrustedProxies []string `json:"trustedProxies,omitempty"` // CIDRs; the header and X-Forwarded-For are only believed from these
	GeoIPFile      string   `json:"geoipFile,omitempty"`      // .mmdb (DB-IP Lite Country, GeoLite2-Country, ...)
	AllowNetworks  []string `json:"allowNetworks,omitempty"`  // CIDRs that always pass: LAN, VPN
	Countries      []string `json:"countries,omitempty"`      // initial allow-list (ISO 3166-1 alpha-2)
	Unknown        string   `json:"unknown,omitempty"`        // "block" (default) or "allow": no country found
	// CacheControl, when set, is added as a Cache-Control header to responses for visitors outside allowNetworks,
	// e.g. "no-cache" so browsers ask again and a removed country is refused at once. Empty = untouched (default).
	// ponytail: added, not replaced: a ResponseWriter wrapper under Yaegi loses Flush or Hijack (streaming or
	// WebSockets). Strict values (no-cache, no-store, max-age=0) win anyway; to loosen an app's caching, ask the app.
	CacheControl string `json:"cacheControl,omitempty"`
}

const (
	geoKey    = "@geo"     // state key of the allow-list; host names never start with "@"
	geoOffKey = "@geo-off" // set (to who/when) while the country check is switched off on the admin page
)

type geoPolicy struct {
	header       string
	net          *netPolicy
	file         string
	unknownAllow bool
	cacheControl string
}

// netPolicy says who the visitor is and whether they are "inside": trusted proxies (whose X-Forwarded-For is
// believed) and allowNetworks (LAN, VPN). Shared by geo, the private mode and locks.
type netPolicy struct {
	trusted []netip.Prefix
	allow   []netip.Prefix
}

// newNetPolicy merges the gate's own trustedProxies/allowNetworks with the ones under geo (v0.6 configs).
func newNetPolicy(c *Config) (*netPolicy, error) {
	trustedList := append([]string{}, c.TrustedProxies...)
	allowList := append([]string{}, c.AllowNetworks...)
	if c.Geo != nil {
		trustedList = append(trustedList, c.Geo.TrustedProxies...)
		allowList = append(allowList, c.Geo.AllowNetworks...)
	}
	trusted, err := parsePrefixes(trustedList)
	if err != nil {
		return nil, fmt.Errorf("trustedProxies: %w", err)
	}
	allow, err := parsePrefixes(allowList)
	if err != nil {
		return nil, fmt.Errorf("allowNetworks: %w", err)
	}
	return &netPolicy{trusted: trusted, allow: allow}, nil
}

func newGeoPolicy(c *GeoConfig, n *netPolicy) (*geoPolicy, error) {
	if c.CountryHeader == "" && c.GeoIPFile == "" {
		return nil, fmt.Errorf("geo: set countryHeader, geoipFile or both")
	}
	if c.CountryHeader != "" && len(n.trusted) == 0 {
		return nil, fmt.Errorf("geo: countryHeader needs trustedProxies, or anyone could send the header")
	}
	if c.Unknown != "" && c.Unknown != "block" && c.Unknown != "allow" {
		return nil, fmt.Errorf("geo: unknown must be block or allow, not %q", c.Unknown)
	}
	if strings.ContainsAny(c.CacheControl, "\r\n") {
		return nil, fmt.Errorf("geo: cacheControl must be one line")
	}
	for _, cc := range c.Countries {
		if normCountry(cc) == "" {
			return nil, fmt.Errorf("geo countries: %q is not a two-letter country code", cc)
		}
	}
	return &geoPolicy{header: c.CountryHeader, net: n, file: c.GeoIPFile, unknownAllow: c.Unknown == "allow",
		cacheControl: strings.TrimSpace(c.CacheControl)}, nil
}

// parsePrefixes accepts CIDRs and single addresses; entries may also be comma-separated (Docker labels, env vars).
func parsePrefixes(list []string) ([]netip.Prefix, error) {
	out := []netip.Prefix{}
	for _, item := range list {
		for _, s := range strings.Split(item, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if !strings.Contains(s, "/") {
				a, err := netip.ParseAddr(s)
				if err != nil {
					return nil, err
				}
				a = a.Unmap()
				out = append(out, netip.PrefixFrom(a, a.BitLen()))
				continue
			}
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, err
			}
			out = append(out, p.Masked())
		}
	}
	return out, nil
}

func inAny(list []netip.Prefix, a netip.Addr) bool {
	for _, p := range list {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func parseIP(s string) netip.Addr {
	s = strings.TrimSpace(s)
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	a, err := netip.ParseAddr(strings.Trim(s, "[]"))
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// client returns the visitor's address and whether the request came through a trusted proxy. Behind one,
// the visitor is the rightmost X-Forwarded-For entry that isn't itself a trusted proxy.
func (n *netPolicy) client(req *http.Request) (netip.Addr, bool) {
	remote := parseIP(req.RemoteAddr)
	if !remote.IsValid() || !inAny(n.trusted, remote) {
		return remote, false
	}
	xff := strings.Split(strings.Join(req.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(xff) - 1; i >= 0; i-- {
		a := parseIP(xff[i])
		if a.IsValid() && !inAny(n.trusted, a) {
			return a, true
		}
	}
	return remote, true
}

// inside reports whether ip is in allowNetworks (LAN, VPN).
func (n *netPolicy) inside(ip netip.Addr) bool { return ip.IsValid() && inAny(n.allow, ip) }

// country finds the visitor's country: the trusted proxy's header first, then the GeoIP file. "" = unknown.
func (g *geoPolicy) country(req *http.Request, ip netip.Addr, viaProxy bool) string {
	if viaProxy && g.header != "" {
		if c := normCountry(req.Header.Get(g.header)); c != "" {
			return c
		}
	}
	if g.file != "" && ip.IsValid() {
		return normCountry(lookupGeoIP(g.file, ip))
	}
	return ""
}

func normCountry(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) != 2 || s[0] < 'A' || s[0] > 'Z' || s[1] < 'A' || s[1] > 'Z' {
		return ""
	}
	return s
}

// geoEntry is one allowed country, permanently or until a time ("ES@2026-11-11T18:00:00+01:00").
type geoEntry struct {
	code  string
	until time.Time
}

func parseGeo(v string) []geoEntry {
	out := []geoEntry{}
	for _, item := range strings.Split(v, ",") {
		parts := strings.SplitN(strings.TrimSpace(item), "@", 2)
		code := normCountry(parts[0])
		if code == "" {
			continue
		}
		var e geoEntry
		e.code = code
		if len(parts) == 2 {
			t, err := time.Parse(time.RFC3339, parts[1])
			if err != nil {
				continue
			}
			e.until = t
		}
		out = append(out, e)
	}
	return out
}

func geoString(list []geoEntry) string {
	sort.Slice(list, func(i, j int) bool { return list[i].code < list[j].code })
	parts := []string{}
	for _, e := range list {
		if e.until.IsZero() {
			parts = append(parts, e.code)
		} else {
			parts = append(parts, e.code+"@"+e.until.Format(time.RFC3339))
		}
	}
	return strings.Join(parts, ",")
}

// geoList returns the allow-list from the state, or the configured starting list while nothing was saved.
func geoList(state map[string]string) []geoEntry {
	if v, ok := state[geoKey]; ok {
		return parseGeo(v)
	}
	return parseGeo(strings.Join(geoDefaults(), ","))
}

func geoAllows(list []geoEntry, code string, t time.Time) bool {
	for _, e := range list {
		if e.code == code && (e.until.IsZero() || t.Before(e.until)) {
			return true
		}
	}
	return false
}

// ponytail: package-level like excludedBy, so the admin instance sees what the gates use; lost on restart.
var (
	geoMu       sync.Mutex
	geoDefault  = map[string][]string{} // gate middleware name -> configured countries
	gateAllow   = map[string]bool{}     // gate middleware name -> has allowNetworks (private mode needs them)
	geoBlocked  = map[string]int{}      // country ("??" = unknown) -> requests refused since start
	geoBlockMax = 300
)

func geoEnabled() bool {
	geoMu.Lock()
	defer geoMu.Unlock()
	return len(geoDefault) > 0
}

// geoDefaults is the union of every gate's configured countries.
func geoDefaults() []string {
	geoMu.Lock()
	defer geoMu.Unlock()
	set := map[string]bool{}
	for _, list := range geoDefault {
		for _, c := range list {
			if c = normCountry(c); c != "" {
				set[c] = true
			}
		}
	}
	out := []string{}
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func noteBlocked(code string) {
	if code == "" {
		code = "??"
	}
	geoMu.Lock()
	if _, ok := geoBlocked[code]; ok || len(geoBlocked) < geoBlockMax {
		geoBlocked[code]++
	}
	geoMu.Unlock()
}

// geoPass decides the request: allowNetworks always pass, then the visitor's country must be on the list.
func (k *KillSwitch) geoPass(req *http.Request) bool {
	g := k.geo
	if g == nil {
		return true
	}
	state := k.load()
	if state[geoOffKey] != "" {
		return true
	}
	ip, viaProxy := g.net.client(req)
	if g.net.inside(ip) {
		return true
	}
	code := g.country(req, ip, viaProxy)
	if code == "" {
		if !g.unknownAllow {
			noteBlocked("")
		}
		return g.unknownAllow
	}
	if geoAllows(geoList(state), code, now()) {
		return true
	}
	noteBlocked(code)
	return false
}

// setGeo changes the allow-list (starting from the configured one on the first save) and records it.
func (k *KillSwitch) setGeo(fn func(list []geoEntry) []geoEntry) error {
	return k.writeState(func(state map[string]string) {
		state[geoKey] = geoString(fn(geoList(state)))
	})
}

// checkGeo removes temporary countries whose time is up (called every second by watch()).
func (k *KillSwitch) checkGeo(t time.Time) {
	state := k.load()
	if _, ok := state[geoKey]; !ok {
		return
	}
	expired := []string{}
	for _, e := range parseGeo(state[geoKey]) {
		if !e.until.IsZero() && !t.Before(e.until) {
			expired = append(expired, e.code)
		}
	}
	if len(expired) == 0 {
		return
	}
	err := k.setGeo(func(list []geoEntry) []geoEntry {
		out := []geoEntry{}
		for _, e := range list {
			if e.until.IsZero() || t.Before(e.until) {
				out = append(out, e)
			}
		}
		return out
	})
	if err != nil {
		log.Printf("killswitch %s: removing expired countries: %v", k.name, err)
		return
	}
	k.record("geo: %s no longer allowed (time is up)", strings.Join(expired, ", "))
}

// postGeo handles the admin page's country forms: allow (permanently or for N days) and remove.
func (k *KillSwitch) postGeo(rw http.ResponseWriter, req *http.Request, action string) {
	fail := func(msg string) {
		http.Redirect(rw, req, req.URL.Path+"?err="+url.QueryEscape(msg)+"#geo", http.StatusSeeOther)
	}
	user, ip := actor(req)
	who := " from " + ip
	if user != "" {
		who = " by " + user + who
	}
	if action == "geo-off" || action == "geo-on" {
		err := k.writeState(func(state map[string]string) {
			if action == "geo-off" {
				state[geoOffKey] = now().Format(time.RFC3339) + who
			} else {
				delete(state, geoOffKey)
			}
		})
		if err != nil {
			log.Printf("killswitch %s: saving countries: %v", k.name, err)
			fail("Save failed: " + err.Error())
			return
		}
		k.record("%s", map[string]string{"geo-off": "geo: country check switched OFF, every country gets through",
			"geo-on": "geo: country check switched on"}[action]+who)
		http.Redirect(rw, req, req.URL.Path+"#geo", http.StatusSeeOther)
		return
	}
	code := normCountry(req.PostForm.Get("country"))
	if code == "" {
		fail("enter a two-letter country code, e.g. ES")
		return
	}
	var msg string
	var err error
	if action == "geo-allow" {
		var until time.Time
		if d := req.PostForm.Get("days"); d != "" {
			n, perr := strconv.Atoi(d)
			if perr != nil || n < 1 || n > 365 {
				fail("days must be between 1 and 365")
				return
			}
			until = now().AddDate(0, 0, n)
		}
		for _, e := range geoList(k.load()) {
			if e.code == code && e.until.IsZero() && !until.IsZero() {
				fail(code + " is already allowed permanently")
				return
			}
		}
		err = k.setGeo(func(list []geoEntry) []geoEntry {
			out := []geoEntry{}
			for _, e := range list {
				if e.code != code {
					out = append(out, e)
				}
			}
			return append(out, geoEntry{code: code, until: until})
		})
		msg = "geo: " + code + " allowed"
		if !until.IsZero() {
			msg += " until " + until.In(time.Local).Format(timeFmt+" MST")
		}
	} else if action == "geo-remove" {
		err = k.setGeo(func(list []geoEntry) []geoEntry {
			out := []geoEntry{}
			for _, e := range list {
				if e.code != code {
					out = append(out, e)
				}
			}
			return out
		})
		msg = "geo: " + code + " removed"
	} else {
		http.Error(rw, "unknown action", http.StatusBadRequest)
		return
	}
	if err != nil {
		log.Printf("killswitch %s: saving countries: %v", k.name, err)
		fail("Save failed: " + err.Error())
		return
	}
	k.record("%s", msg+who)
	http.Redirect(rw, req, req.URL.Path+"#geo", http.StatusSeeOther)
}

func geoForm(action, code, label, extra string) string {
	return `<form method="post"><input type="hidden" name="action" value="` + action + `"><input type="hidden" name="country" value="` +
		html.EscapeString(code) + `">` + extra + `<button title="` + html.EscapeString(label) + `" aria-label="` + html.EscapeString(label) + `">` +
		html.EscapeString(map[string]string{"geo-remove": "×", "geo-allow": "allow"}[action]) + `</button></form>`
}

// geoHTML is the admin page's Countries card: the allow-list, a form to add one, and what was refused.
func geoHTML(state map[string]string, t time.Time) string {
	var b strings.Builder
	b.WriteString(`<h2 id="geo">Countries</h2><p>Only visitors from these countries get through, on every site behind a gate with <code>geo</code> ` +
		`(always-on hosts included). <code>allowNetworks</code> (LAN, VPN) always pass.</p><div class="card">`)
	off := state[geoOffKey]
	if off != "" {
		since := off
		if i := strings.Index(off, " "); i > 0 {
			if ts, err := time.Parse(time.RFC3339, off[:i]); err == nil {
				since = ts.In(time.Local).Format(timeFmt) + off[i:]
			}
		}
		b.WriteString(`<div class="row all"><div class="host">Country check<small class="bad">Off: every country gets through (since ` +
			html.EscapeString(since) + `)</small></div><span class="pill block">off</span>` +
			`<form method="post"><button class="on" name="action" value="geo-on">turn on</button></form></div>`)
	} else {
		b.WriteString(`<div class="row all"><div class="host">Country check<small>The list below is enforced</small></div><span class="pill on">on</span>` +
			`<form method="post"><button class="block" name="action" value="geo-off">turn off</button></form></div>`)
	}
	b.WriteString(`<div class="row"><div class="chips">`)
	list := geoList(state)
	sort.Slice(list, func(i, j int) bool { return list[i].code < list[j].code })
	for _, e := range list {
		label := html.EscapeString(e.code)
		if !e.until.IsZero() {
			label += ` <small>until ` + html.EscapeString(e.until.In(time.Local).Format(timeFmt)) + `</small>`
		}
		b.WriteString(`<span class="chip">` + label + geoForm("geo-remove", e.code, "Remove "+e.code, "") + `</span>`)
	}
	if len(list) == 0 {
		b.WriteString(`<p class="warn">No country is allowed: only allowNetworks get through.</p>`)
	}
	b.WriteString(`</div></div><div class="row"><form method="post" style="flex-wrap:wrap;align-items:center">` +
		`<input type="hidden" name="action" value="geo-allow"><input name="country" placeholder="ES" maxlength="2" pattern="[A-Za-z]{2}" ` +
		`required aria-label="Country code" style="flex:0 0 5rem;text-transform:uppercase">` +
		`<select name="days" aria-label="How long"><option value="">permanently</option><option value="1">for 1 day</option>` +
		`<option value="7">for 7 days</option><option value="14">for 14 days</option><option value="30">for 30 days</option></select>` +
		`<button>Allow</button>` +
		`<a href="https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2#Officially_assigned_code_elements" target="_blank" rel="noopener noreferrer">country codes</a>` +
		`</form></div>`)
	geoMu.Lock()
	type count struct {
		code string
		n    int
	}
	counts := []count{}
	for c, n := range geoBlocked {
		counts = append(counts, count{c, n})
	}
	geoMu.Unlock()
	sort.Slice(counts, func(i, j int) bool {
		if counts[i].n != counts[j].n {
			return counts[i].n > counts[j].n
		}
		return counts[i].code < counts[j].code
	})
	if len(counts) > 0 {
		b.WriteString(`<div class="row"><div class="host">Refused since Traefik started<small>?? = no country found ` +
			`(direct hits on the IP, or not in the GeoIP file)</small></div><div class="chips">`)
		for i, c := range counts {
			if i == 30 {
				break
			}
			allow := ""
			if c.code != "??" && !geoAllows(list, c.code, t) {
				allow = geoForm("geo-allow", c.code, "Allow "+c.code+" permanently", "")
			}
			b.WriteString(`<span class="chip">` + html.EscapeString(c.code) + ` <small>` + strconv.Itoa(c.n) + `</small>` + allow + `</span>`)
		}
		b.WriteString(`</div></div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}
