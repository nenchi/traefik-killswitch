package traefik_killswitch

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LockConfig turns on the password lock (htaccess-style Basic auth) for a gate middleware. Lock groups and
// which site uses which group are edited on the admin page; nothing about passwords goes in the config.
type LockConfig struct {
	Enabled     bool `json:"enabled,omitempty"`
	MaxFailures int  `json:"maxFailures,omitempty"` // wrong logins per IP before a ban (default 5)
	BanMinutes  int  `json:"banMinutes,omitempty"`  // ban length, also the window failures are counted in (default 10)
}

type lockPolicy struct {
	maxFailures int
	ban         time.Duration
}

func newLockPolicy(c *LockConfig) (*lockPolicy, error) {
	if c == nil || !c.Enabled {
		return nil, nil
	}
	if c.MaxFailures < 0 || c.BanMinutes < 0 {
		return nil, fmt.Errorf("locks: maxFailures and banMinutes must not be negative")
	}
	lp := &lockPolicy{maxFailures: 5, ban: 10 * time.Minute}
	if c.MaxFailures > 0 {
		lp.maxFailures = c.MaxFailures
	}
	if c.BanMinutes > 0 {
		lp.ban = time.Duration(c.BanMinutes) * time.Minute
	}
	return lp, nil
}

const (
	lockPrefix  = "@lock:"      // "@lock:<host>" = "<group>" or "<group>|outside"
	groupPrefix = "@lockgroup:" // "@lockgroup:<group>" = "user:<hash>,user2:<hash>"
	modePrivate = "private"     // only allowNetworks (LAN, VPN) get through
	lockOutside = "outside"     // lock only visitors from countries not on the geo list
	hashScheme  = "pbkdf2-sha256"
	hashIter    = 60000 // ponytail: interpreted loop under Yaegi; raise if logins stay fast enough on real hardware
)

var lockGates = map[string]bool{} // gate middleware name -> locks enabled (guarded by geoMu)

func locksEnabled() bool {
	geoMu.Lock()
	defer geoMu.Unlock()
	return len(lockGates) > 0
}

// pbkdf2SHA256 is PBKDF2 (RFC 8018) with HMAC-SHA256 and one 32-byte block, built from the standard library
// (crypto/pbkdf2 is too new for Yaegi's stdlib symbols).
func pbkdf2SHA256(password, salt []byte, iter int) []byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	u := mac.Sum(nil)
	t := make([]byte, len(u))
	copy(t, u)
	for i := 1; i < iter; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(u[:0])
		for j := range t {
			t[j] ^= u[j]
		}
	}
	return t
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return hashScheme + "$" + strconv.Itoa(hashIter) + "$" + enc.EncodeToString(salt) + "$" +
		enc.EncodeToString(pbkdf2SHA256([]byte(password), salt, hashIter)), nil
}

func checkHash(stored, password string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != hashScheme {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 || iter > 10000000 {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[2])
	want, err2 := enc.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	return subtle.ConstantTimeCompare(pbkdf2SHA256([]byte(password), salt, iter), want) == 1
}

// groupUsers parses a lock group's value into user -> hash.
func groupUsers(v string) map[string]string {
	users := map[string]string{}
	for _, item := range strings.Split(v, ",") {
		i := strings.Index(item, ":")
		if i > 0 {
			users[item[:i]] = item[i+1:]
		}
	}
	return users
}

func groupString(users map[string]string) string {
	names := []string{}
	for u := range users {
		names = append(names, u)
	}
	sort.Strings(names)
	parts := []string{}
	for _, u := range names {
		parts = append(parts, u+":"+users[u])
	}
	return strings.Join(parts, ",")
}

func parseLock(v string) (string, string) {
	parts := strings.SplitN(v, "|", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return parts[0], ""
}

// validName allows plain names for groups and users: letters, digits, - _ . @ (no separators of the state format).
func validName(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == '@') {
			return false
		}
	}
	return true
}

// ponytail: in-memory, per Traefik process; lost on restart, which only shortens running bans.
var (
	loginMu    sync.Mutex
	failures   = map[string]*failCount{} // client IP -> failed logins in the current window
	loginCache = map[[32]byte]time.Time{}
	cacheTTL   = 10 * time.Minute
	cacheMax   = 1000
	failMax    = 10000
)

type failCount struct {
	n     int
	first time.Time
	max   int           // the gate's maxFailures when counted
	ban   time.Duration // and its ban length
}

type banInfo struct {
	ip    string
	n     int
	until time.Time
}

// bans lists the addresses that are banned right now, soonest end first.
func bans(t time.Time) []banInfo {
	loginMu.Lock()
	defer loginMu.Unlock()
	out := []banInfo{}
	for ip, f := range failures {
		if f.n >= f.max && t.Before(f.first.Add(f.ban)) {
			out = append(out, banInfo{ip: ip, n: f.n, until: f.first.Add(f.ban)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].until.Before(out[j].until) })
	return out
}

// unban forgets an address's failed logins; false if it wasn't banned.
func unban(ip string, t time.Time) bool {
	loginMu.Lock()
	defer loginMu.Unlock()
	f := failures[ip]
	if f == nil || f.n < f.max || !t.Before(f.first.Add(f.ban)) {
		return false
	}
	delete(failures, ip)
	return true
}

// banned reports whether ip has used up its failed logins; the ban ends one window after the first failure.
func (lp *lockPolicy) banned(ip string, t time.Time) bool {
	loginMu.Lock()
	defer loginMu.Unlock()
	f := failures[ip]
	if f == nil {
		return false
	}
	if t.Sub(f.first) >= lp.ban {
		delete(failures, ip)
		return false
	}
	return f.n >= lp.maxFailures
}

// fail counts a wrong login and reports whether it just triggered the ban.
func (lp *lockPolicy) fail(ip string, t time.Time) bool {
	loginMu.Lock()
	defer loginMu.Unlock()
	f := failures[ip]
	if f == nil || t.Sub(f.first) >= lp.ban {
		if len(failures) >= failMax {
			failures = map[string]*failCount{} // ponytail: crude cap against address floods
		}
		f = &failCount{first: t}
		failures[ip] = f
	}
	f.max = lp.maxFailures
	f.ban = lp.ban
	f.n++
	return f.n == lp.maxFailures
}

// loginOK checks user/password against the group, caching successes so the slow hash runs once per login.
func loginOK(groupValue, group, user, password string, t time.Time) bool {
	stored, ok := groupUsers(groupValue)[user]
	if !ok {
		return false
	}
	key := sha256.Sum256([]byte(group + "\x00" + user + "\x00" + password + "\x00" + stored))
	loginMu.Lock()
	exp, hit := loginCache[key]
	loginMu.Unlock()
	if hit && t.Before(exp) {
		return true
	}
	if !checkHash(stored, password) {
		return false
	}
	loginMu.Lock()
	if len(loginCache) >= cacheMax {
		loginCache = map[[32]byte]time.Time{}
	}
	loginCache[key] = t.Add(cacheTTL)
	loginMu.Unlock()
	return true
}

// secure is true when the browser's connection is HTTPS: TLS to Traefik, or a trusted proxy saying so.
func (k *KillSwitch) secure(req *http.Request) bool {
	if req.TLS != nil {
		return true
	}
	remote := parseIP(req.RemoteAddr)
	return remote.IsValid() && inAny(k.net.trusted, remote) && strings.EqualFold(req.Header.Get("X-Forwarded-Proto"), "https")
}

// requireLogin answers the request unless it carries a valid login for group: 401 asks the browser for one,
// 429 while the client is banned, 403 over plain HTTP (the password would travel unencrypted). True = logged in.
func (k *KillSwitch) requireLogin(rw http.ResponseWriter, req *http.Request, host, group string, state map[string]string) bool {
	if !k.secure(req) {
		http.Error(rw, "This site is locked. Logging in needs HTTPS.", http.StatusForbidden)
		return false
	}
	ipAddr, _ := k.net.client(req)
	ip := ipAddr.String()
	t := now()
	if k.lock.banned(ip, t) {
		rw.Header().Set("Retry-After", strconv.Itoa(int(k.lock.ban.Seconds())))
		http.Error(rw, "Too many failed logins. Try again later.", http.StatusTooManyRequests)
		return false
	}
	user, password, ok := req.BasicAuth()
	if ok && loginOK(state[groupPrefix+group], group, user, password, t) {
		return true
	}
	if ok && k.lock.fail(ip, t) {
		logInfo("lock: %s banned for %s after %d failed logins (%s)", ip, k.lock.ban, k.lock.maxFailures, host)
	}
	realm := strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < ' ' {
			return -1
		}
		return r
	}, host)
	rw.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`", charset="UTF-8"`)
	http.Error(rw, "Login required.", http.StatusUnauthorized)
	return false
}

// postLockGroup handles the Locks card: set a user's password (creating the group), remove a user, delete a group.
func (k *KillSwitch) postLockGroup(rw http.ResponseWriter, req *http.Request, action string) {
	fail := func(msg string) {
		http.Redirect(rw, req, req.URL.Path+"?err="+url.QueryEscape(msg)+"#locks", http.StatusSeeOther)
	}
	if action == "lock-unban" {
		ip := strings.TrimSpace(req.PostForm.Get("ip"))
		if !unban(ip, now()) {
			fail(ip + " is not banned (any more)")
			return
		}
		user, from := actor(req)
		who := " from " + from
		if user != "" {
			who = " by " + user + who
		}
		k.record("lock: %s unbanned%s", ip, who)
		http.Redirect(rw, req, req.URL.Path+"#locks", http.StatusSeeOther)
		return
	}
	group := strings.TrimSpace(req.PostForm.Get("group"))
	if !validName(group, 32) {
		fail("group names use letters, digits, - _ . @ (up to 32)")
		return
	}
	user, ip := actor(req)
	who := " from " + ip
	if user != "" {
		who = " by " + user + who
	}
	name := strings.TrimSpace(req.PostForm.Get("user"))
	state := k.load()
	var msg string
	var err error
	switch action {
	case "lock-user-set":
		password := req.PostForm.Get("password")
		if !validName(name, 64) {
			fail("user names use letters, digits, - _ . @ (up to 64)")
			return
		}
		if len(password) < 8 {
			fail("use a password of at least 8 characters")
			return
		}
		hash, herr := hashPassword(password)
		if herr != nil {
			fail("hashing failed: " + herr.Error())
			return
		}
		_, existed := groupUsers(state[groupPrefix+group])[name]
		err = k.writeState(func(st map[string]string) {
			users := groupUsers(st[groupPrefix+group])
			users[name] = hash
			st[groupPrefix+group] = groupString(users)
		})
		msg = "lock: user " + name + " added to " + group
		if existed {
			msg = "lock: password changed for " + name + " in " + group
		}
	case "lock-user-remove":
		users := groupUsers(state[groupPrefix+group])
		if _, ok := users[name]; !ok {
			fail(name + " is not in " + group)
			return
		}
		if len(users) == 1 && len(sitesLockedBy(state, group)) > 0 {
			fail("that's the last user of " + group + ", which still locks " + strings.Join(sitesLockedBy(state, group), ", ") +
				". Unlock those sites or delete the group instead")
			return
		}
		err = k.writeState(func(st map[string]string) {
			users := groupUsers(st[groupPrefix+group])
			delete(users, name)
			if len(users) == 0 {
				delete(st, groupPrefix+group)
			} else {
				st[groupPrefix+group] = groupString(users)
			}
		})
		msg = "lock: user " + name + " removed from " + group
	case "lock-group-delete":
		if sites := sitesLockedBy(state, group); len(sites) > 0 {
			fail(group + " still locks " + strings.Join(sites, ", ") + ". Unlock those sites first")
			return
		}
		err = k.writeState(func(st map[string]string) { delete(st, groupPrefix+group) })
		msg = "lock: group " + group + " deleted"
	default:
		http.Error(rw, "unknown action", http.StatusBadRequest)
		return
	}
	if err != nil {
		log.Printf("killswitch %s: saving locks: %v", k.name, err)
		fail("Save failed: " + err.Error())
		return
	}
	k.record("%s", msg+who) // never the password
	http.Redirect(rw, req, req.URL.Path+"#locks", http.StatusSeeOther)
}

func sitesLockedBy(state map[string]string, group string) []string {
	out := []string{}
	for key, v := range state {
		if g, _ := parseLock(v); strings.HasPrefix(key, lockPrefix) && g == group {
			out = append(out, strings.TrimPrefix(key, lockPrefix))
		}
	}
	sort.Strings(out)
	return out
}

func lockGroups(state map[string]string) []string {
	out := []string{}
	for key := range state {
		if strings.HasPrefix(key, groupPrefix) {
			out = append(out, strings.TrimPrefix(key, groupPrefix))
		}
	}
	sort.Strings(out)
	return out
}

// postLock sets or clears the lock of one site or a group row.
func (k *KillSwitch) postLock(rw http.ResponseWriter, req *http.Request, hosts []string) {
	fail := func(msg string) {
		http.Redirect(rw, req, req.URL.Path+"?err="+url.QueryEscape(msg), http.StatusSeeOther)
	}
	group := req.PostForm.Get("lock")
	when := req.PostForm.Get("when")
	state := k.load()
	if group != "" {
		if _, ok := state[groupPrefix+group]; !ok {
			fail("unknown lock group " + group)
			return
		}
		if when != "" && when != lockOutside {
			fail("unknown lock option " + when)
			return
		}
		if when == lockOutside && !geoEnabled() {
			fail("\"only outside allowed countries\" needs a gate with geo")
			return
		}
	}
	for _, host := range hosts {
		if host == allHosts {
			fail("locks are per site; lock the sites one by one")
			return
		}
		if isExcluded(excludedHosts(), host) {
			fail(host + " is in excludeHosts and is never locked")
			return
		}
		if group != "" {
			if refuse, _ := k.checkHost(host, modeBlock, ""); refuse != "" {
				fail(refuse)
				return
			}
		}
	}
	user, ip := actor(req)
	who := " from " + ip
	if user != "" {
		who = " by " + user + who
	}
	value := group
	label := "locked with " + group
	if when == lockOutside {
		value += "|" + lockOutside
		label += " (only outside allowed countries)"
	}
	for _, host := range hosts {
		err := k.writeState(func(st map[string]string) {
			if group == "" {
				delete(st, lockPrefix+host)
			} else {
				st[lockPrefix+host] = value
			}
		})
		if err != nil {
			log.Printf("killswitch %s: saving lock: %v", k.name, err)
			fail("Save failed for " + host + ": " + err.Error())
			return
		}
		if group == "" {
			k.record("lock: %s unlocked%s", host, who)
		} else {
			k.record("lock: %s %s%s", host, label, who)
		}
	}
	http.Redirect(rw, req, req.URL.Path, http.StatusSeeOther)
}

// lockHTML is a site row's lock: the current one, and a form to change it.
func lockHTML(hosts []string, state map[string]string, groups []string) string {
	cur, when := parseLock(state[lockPrefix+hosts[0]])
	for _, h := range hosts[1:] {
		if state[lockPrefix+h] != state[lockPrefix+hosts[0]] {
			cur = "" // mixed: show the form unselected
			when = ""
		}
	}
	var b strings.Builder
	if cur != "" {
		label := "🔒 " + cur
		if when == lockOutside {
			label += " · only outside allowed countries"
		}
		b.WriteString(`<div class="sched">Lock <span class="pill maint">` + html.EscapeString(label) + `</span></div>`)
	}
	b.WriteString(`<details><summary>Lock…</summary><form method="post">` + hostFields(hosts) +
		`<input type="hidden" name="action" value="lock"><select name="lock" aria-label="Lock group"><option value="">no lock</option>`)
	for _, g := range groups {
		sel := ""
		if g == cur {
			sel = " selected"
		}
		b.WriteString(`<option value="` + html.EscapeString(g) + `"` + sel + `>` + html.EscapeString(g) + `</option>`)
	}
	b.WriteString(`</select>`)
	if geoEnabled() {
		sel := ""
		if when == lockOutside {
			sel = " selected"
		}
		b.WriteString(`<select name="when" aria-label="When"><option value="">always</option><option value="outside"` + sel +
			`>only outside allowed countries</option></select>`)
	}
	b.WriteString(`<button>Save lock</button></form></details>`)
	return b.String()
}

// locksHTML is the Locks card: every group with its users, and forms to add users or delete groups.
func locksHTML(state map[string]string) string {
	var b strings.Builder
	b.WriteString(`<h2 id="locks">Locks</h2><p>A lock asks for a user name and password (Basic auth, HTTPS only) before a site opens. ` +
		`<code>allowNetworks</code> (LAN, VPN) never get asked. Pick a group per site under <b>Lock…</b>; several sites can share one.</p><div class="card">`)
	groups := lockGroups(state)
	for _, g := range groups {
		users := groupUsers(state[groupPrefix+g])
		names := []string{}
		for u := range users {
			names = append(names, u)
		}
		sort.Strings(names)
		sites := sitesLockedBy(state, g)
		used := "not used yet"
		if len(sites) > 0 {
			used = "locks " + strings.Join(sites, ", ")
		}
		b.WriteString(`<div class="row"><div class="host">` + html.EscapeString(g) + `<small>` + html.EscapeString(used) + `</small></div><div class="chips">`)
		for _, u := range names {
			b.WriteString(`<span class="chip">` + html.EscapeString(u) + `<form method="post"><input type="hidden" name="action" value="lock-user-remove">` +
				`<input type="hidden" name="group" value="` + html.EscapeString(g) + `"><input type="hidden" name="user" value="` + html.EscapeString(u) +
				`"><button title="Remove ` + html.EscapeString(u) + `" aria-label="Remove ` + html.EscapeString(u) + `">×</button></form></span>`)
		}
		b.WriteString(`</div>`)
		if len(sites) == 0 {
			b.WriteString(`<form method="post"><input type="hidden" name="action" value="lock-group-delete"><input type="hidden" name="group" value="` +
				html.EscapeString(g) + `"><button class="block">delete group</button></form>`)
		}
		b.WriteString(`</div>`)
	}
	if len(groups) == 0 {
		b.WriteString(`<div class="row"><p>No lock groups yet. Add a user below to create one.</p></div>`)
	}
	b.WriteString(`<div class="row"><form method="post" style="flex-wrap:wrap;align-items:center"><input type="hidden" name="action" value="lock-user-set">` +
		`<input name="group" placeholder="group, e.g. family" required list="lock-groups" style="flex:1 1 9rem" aria-label="Group">` +
		`<input name="user" placeholder="user" required autocomplete="off" style="flex:1 1 7rem" aria-label="User">` +
		`<input name="password" type="password" placeholder="password (8+)" required minlength="8" autocomplete="new-password" style="flex:1 1 9rem" aria-label="Password">` +
		`<button>Set password</button></form><datalist id="lock-groups">`)
	for _, g := range groups {
		b.WriteString(`<option value="` + html.EscapeString(g) + `">`)
	}
	b.WriteString(`</datalist></div>`)
	if list := bans(now()); len(list) > 0 {
		b.WriteString(`<div class="row"><div class="host">Banned addresses<small>Too many wrong passwords. Unban lets them try again at once.</small></div><div class="chips">`)
		for _, ban := range list {
			b.WriteString(`<span class="chip">` + html.EscapeString(ban.ip) + ` <small>` + strconv.Itoa(ban.n) + ` wrong · until ` +
				html.EscapeString(ban.until.In(time.Local).Format("15:04")) + `</small><form method="post"><input type="hidden" name="action" value="lock-unban">` +
				`<input type="hidden" name="ip" value="` + html.EscapeString(ban.ip) + `"><button title="Unban ` + html.EscapeString(ban.ip) +
				`">unban</button></form></span>`)
		}
		b.WriteString(`</div></div>`)
	}
	b.WriteString(`<div class="row"><p>Setting an existing user's password changes it. Passwords are stored only as salted hashes ` +
		`(PBKDF2-SHA256) in the state file. After the configured number of wrong passwords an address is banned for a while (429).</p></div></div>`)
	return b.String()
}
