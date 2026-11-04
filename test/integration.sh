#!/usr/bin/env bash
# Runs a real Traefik with this plugin loaded via localPlugins (Yaegi) and checks the switch end to end.
# Usage: TRAEFIK=/path/to/traefik test/integration.sh
set -euo pipefail
cd "$(dirname "$0")/.."
TRAEFIK=${TRAEFIK:-traefik}
RUN=test/run
rm -rf "$RUN" && mkdir -p "$RUN/plugins-local/src/github.com/nenchi/traefik-killswitch"
cp go.mod .traefik.yml $(ls *.go | grep -v _test.go) "$RUN/plugins-local/src/github.com/nenchi/traefik-killswitch/"
STATE="$PWD/$RUN/state.json"
mkdir -p "$RUN/pages" && echo "default-page" > "$RUN/pages/maintenance.html" && echo "downtime-page" > "$RUN/pages/downtime.html" && echo "back: {{back|soon}}" > "$RUN/pages/back.html"

cat > "$RUN/static.yml" <<YML
entryPoints:
  web:
    address: "127.0.0.1:18080"
    http:
      middlewares: [gate@file]
  admin:
    address: "127.0.0.1:18081"
  traefik:
    address: "127.0.0.1:18082"
  geo:
    address: "127.0.0.1:18083"
    forwardedHeaders:
      trustedIPs: ["127.0.0.1"]
    http:
      middlewares: [geogate@file]
api:
  insecure: true
providers:
  file:
    filename: dynamic.yml
experimental:
  localPlugins:
    killswitch:
      moduleName: github.com/nenchi/traefik-killswitch
log:
  level: INFO
YML

cat > "$RUN/dynamic.yml" <<YML
http:
  middlewares:
    gate:
      plugin:
        killswitch:
          stateFile: $STATE
          maintenanceFile: $PWD/$RUN/pages/maintenance.html
          excludeHosts: [ks.lan, "*.vpn.lan"]
    geogate:
      plugin:
        killswitch:
          stateFile: $STATE
          allowNetworks: ["192.168.0.0/16"]
          locks:
            enabled: true
            maxFailures: 3
          geo:
            countryHeader: X-Country
            trustedProxies: ["127.0.0.1/32"]
            countries: [DE]
    ks-admin:
      plugin:
        killswitch:
          stateFile: $STATE
          admin: true
          apiURL: http://127.0.0.1:18082
  services:
    msvc:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:9
  routers:
    a:
      entryPoints: [web]
      rule: Host(\`a.lan\`)
      service: noop@internal
    b:
      entryPoints: [web]
      rule: Host(\`b.lan\`)
      service: noop@internal
    multi:
      entryPoints: [web]
      rule: Host(\`m1.test.lan\`) || Host(\`m2.test.lan\`)
      service: msvc
    multi-other-domain:
      entryPoints: [web]
      rule: Host(\`m3.other.lan\`)
      service: msvc
    vpn:
      entryPoints: [web]
      rule: Host(\`x.vpn.lan\`)
      service: noop@internal
    geo-site:
      entryPoints: [geo]
      rule: Host(\`g.lan\`)
      service: noop@internal
    admin-gated-ep:
      entryPoints: [web]
      rule: Host(\`ks.lan\`)
      middlewares: [ks-admin]
      service: noop@internal
    unprotected:
      entryPoints: [admin]
      rule: Host(\`c.lan\`)
      service: noop@internal
    admin:
      entryPoints: [admin]
      rule: PathPrefix(\`/\`)
      middlewares: [ks-admin]
      service: noop@internal
YML

(cd "$RUN" && exec "$TRAEFIK" --configfile=static.yml >traefik.log 2>&1) &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT

code() { curl -s -o /dev/null -w '%{http_code}' -H "Host: $1" http://127.0.0.1:18080/; }
# A switch applies within ~1s (state file is re-checked at most once a second): poll up to 3s for the wanted code.
code_within() { local c; for _ in $(seq 15); do c=$(code "$1"); [ "$c" = "$2" ] && break; sleep 0.2; done; echo "$c"; }
set_mode() { curl -s -o /dev/null -w '%{http_code}' -d "host=$1&mode=$2&template=${3:-}" http://127.0.0.1:18081/; }
body_within() { local b; for _ in $(seq 15); do b=$(curl -s -H "Host: $1" http://127.0.0.1:18080/); [ "$b" = "$2" ] && break; sleep 0.2; done; echo "$b"; }
expect() { [ "$2" = "$3" ] && echo "ok   $1" || { echo "FAIL $1: got $2, want $3"; cat "$RUN/traefik.log"; exit 1; }; }

for _ in $(seq 50); do [ "$(code a.lan)" = 200 ] && break; sleep 0.2; done

# noop@internal answers 418 when the request passes through.
expect "a passes"            "$(code_within a.lan 418)" 418
expect "admin page"          "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18081/)" 200
expect "set a=maint"         "$(set_mode a.lan maint)" 303
expect "a maintenance"       "$(code_within a.lan 503)" 503
expect "a default page"      "$(body_within a.lan default-page)" default-page
expect "set a=maint:downtime" "$(set_mode a.lan maint downtime)" 303
expect "a downtime page"     "$(body_within a.lan downtime-page)" downtime-page
# no polling: an admin change must apply on the very next request
expect "switch page instantly" "$(set_mode a.lan maint back)" 303
expect "new page on next request" "$(curl -s -H 'Host: a.lan' http://127.0.0.1:18080/)" "back: soon"
expect "back to downtime"    "$(set_mode a.lan maint downtime)" 303
expect "instant again"       "$(curl -s -H 'Host: a.lan' http://127.0.0.1:18080/)" downtime-page
expect "b still passes"      "$(code_within b.lan 418)" 418
expect "set *=block"         "$(set_mode '*' block)" 303
expect "b blocked by global" "$(code_within b.lan 403)" 403
expect "*.vpn.lan stays on"  "$(code x.vpn.lan)" 418
expect "admin not gated"     "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18081/)" 200
expect "excluded host passes" "$(code_within ks.lan 200)" 200
expect "set *=on"            "$(set_mode '*' on)" 303
expect "a back to maint"     "$(code_within a.lan 503)" 503
expect "set a=on"            "$(set_mode a.lan on)" 303
expect "a passes again"      "$(code_within a.lan 418)" 418
post() { curl -s -o /dev/null -w '%{http_code}' "$@" http://127.0.0.1:18081/; }
FROM=$(date -d '-1 min' +%Y-%m-%dT%H:%M); TO=$(date -d '+1 hour' +%Y-%m-%dT%H:%M)
expect "schedule b block now" "$(post -d "host=b.lan&action=schedule&mode=block&from=$FROM&to=$TO")" 303
expect "b blocked by window" "$(code_within b.lan 403)" 403
for _ in $(seq 15); do grep -q 'INF KILL-SWITCH: schedule active since' "$RUN/traefik.log" && break; sleep 0.2; done
expect "cancel b window"     "$(post -d "host=b.lan&action=unschedule")" 303
expect "b passes again"      "$(code_within b.lan 418)" 418
expect "set b=maint:back"    "$(post -d "host=b.lan&mode=maint&template=back")" 303
expect "manual maint says soon" "$(body_within b.lan 'back: soon')" "back: soon"
FROM=$(date -d '-1 min' +%Y-%m-%dT%H:%M); TO=$(date -d '+1 hour' +%Y-%m-%dT%H:%M); WANT="back: $(date -d "$TO" '+%a %d %b %H:%M %Z')"
expect "schedule b maint:back" "$(post -d "host=b.lan&action=schedule&mode=maint&template=back&from=$FROM&to=$TO")" 303
expect "window shows its end" "$(body_within b.lan "$WANT")" "$WANT"
expect "set b=on"            "$(post -d "host=b.lan&mode=on")" 303
expect "cancel b window again" "$(post -d "host=b.lan&action=unschedule")" 303
expect "b passes after cancel" "$(code_within b.lan 418)" 418
FROM=$(date -d '+1 hour' +%Y-%m-%dT%H:%M); TO=$(date -d '+2 hour' +%Y-%m-%dT%H:%M)
expect "schedule b later"    "$(post -d "host=b.lan&action=schedule&mode=maint&from=$FROM&to=$TO")" 303
expect "b passes before window" "$(code_within b.lan 418)" 418
loc() { curl -s -o /dev/null -w '%{redirect_url}' "$@" http://127.0.0.1:18081/; }
case "$(loc -d 'host=c.lan&mode=block')" in *unprotected%40file*) echo "ok   unprotected host c.lan refused";; *) echo "FAIL c.lan not refused"; exit 1;; esac
case "$(loc -d 'host=typo.lan&mode=block')" in *No+Traefik+router*) echo "ok   unknown host refused";; *) echo "FAIL typo.lan not refused"; exit 1;; esac
FROM=$(date -d '+1 day' +%Y-%m-%dT03:00); TO=$(date -d '+1 day' +%Y-%m-%dT04:00)
expect "schedule a weekly"   "$(post -d "host=a.lan&action=schedule&mode=maint&repeat=weekly&from=$FROM&to=$TO")" 303
curl -s http://127.0.0.1:18081/ | grep -q "every $(date -d '+1 day' +%A) 03:00–04:00</b> (next" && echo "ok   weekly window shown with next run" || { echo "FAIL weekly window"; exit 1; }
# a one-off that already ended is removed by the background check within ~2s
python3 - "$STATE" <<'PY'
import json,sys,datetime,os
p=sys.argv[1]; s=json.load(open(p)); tz=datetime.datetime.now().astimezone().tzinfo
f=lambda m: (datetime.datetime.now(tz)-datetime.timedelta(minutes=m)).isoformat(timespec="seconds")
s["old.lan"]="on|block|%s|%s" % (f(30), f(10)); json.dump(s, open(p+".tmp","w")); os.rename(p+".tmp", p)
PY
for _ in $(seq 15); do grep -q old.lan "$STATE" || break; sleep 0.2; done
grep -q old.lan "$STATE" && { echo "FAIL ended window not removed"; exit 1; } || echo "ok   ended window removed automatically"
curl -s 'http://127.0.0.1:18081/?view=history' | grep -q 'schedule for old.lan' && echo "ok   history page shows removal" || { echo "FAIL history page"; exit 1; }
curl -s http://127.0.0.1:18081/ | grep -q '>m1.test.lan + m2.test.lan<' && echo "ok   one service + domain form one row" || { echo "FAIL m1+m2 not grouped"; exit 1; }
curl -s http://127.0.0.1:18081/ | grep -q '>m3.other.lan<' && echo "ok   same service, other domain stays apart" || { echo "FAIL m3 not separate"; exit 1; }
expect "switch group"        "$(post -d 'host=m1.test.lan&host=m2.test.lan&mode=block')" 303
expect "m1 blocked"          "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: m1.test.lan' http://127.0.0.1:18080/)" 403
expect "m2 blocked"          "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: m2.test.lan' http://127.0.0.1:18080/)" 403
expect "m3 untouched"        "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: m3.other.lan' http://127.0.0.1:18080/)" 502
expect "group back on"       "$(post -d 'host=m1.test.lan&host=m2.test.lan&mode=on')" 303
curl -s -b 'ks_group=off' http://127.0.0.1:18081/ | grep -q 'm1.test.lan + m2.test.lan' && { echo "FAIL grouping off still groups"; exit 1; } || echo "ok   grouping off lists names separately"
PAGE=$(curl -s http://127.0.0.1:18081/)
echo "$PAGE" | grep -q '<li>c.lan <small>(unprotected@file)' && echo "ok   admin lists c.lan as not protected" || { echo "FAIL c.lan not listed as unprotected"; exit 1; }
echo "$PAGE" | grep -q '(upcoming)' && echo "ok   admin shows upcoming window" || { echo "FAIL upcoming window not shown"; exit 1; }
echo "$PAGE" | grep -q 'value="b.lan"' && echo "ok   admin lists seen host b.lan" || { echo "FAIL admin does not list seen host"; exit 1; }
echo "$PAGE" | grep -q '<li>ks.lan</li>' && echo "ok   admin lists excluded host ks.lan as always on" || { echo "FAIL excluded host not shown"; exit 1; }
gcode() { curl -s -o /dev/null -w '%{http_code}' -H 'Host: g.lan' ${1:+-H "X-Country: $1"} http://127.0.0.1:18083/; }
expect "geo: allowed country" "$(gcode DE)" 418
expect "geo: other country"   "$(gcode ES)" 403
expect "geo: no country"      "$(gcode)" 403
curl -s http://127.0.0.1:18081/ | grep -q 'ES <small>1</small>' && echo "ok   admin shows refused ES" || { echo "FAIL refused ES not shown"; exit 1; }
expect "geo: allow ES 7 days" "$(post -d 'action=geo-allow&country=ES&days=7')" 303
expect "geo: ES on next request" "$(gcode ES)" 418
expect "geo: remove DE"       "$(post -d 'action=geo-remove&country=DE')" 303
expect "geo: DE now refused"  "$(gcode DE)" 403
expect "geo: web gate has no geo" "$(code a.lan)" 418
expect "geo: switch check off" "$(post -d 'action=geo-off')" 303
expect "geo: off lets CN in"  "$(gcode CN)" 418
expect "geo: switch check on"  "$(post -d 'action=geo-on')" 303
expect "geo: on refuses CN"   "$(gcode CN)" 403
# locks: curl plays a trusted proxy (127.0.0.1) forwarding an outside visitor over HTTPS
lcode() { curl -s -o /dev/null -w '%{http_code}' -H 'Host: g.lan' -H 'X-Country: ES' -H "X-Forwarded-For: ${XFF:-203.0.113.5}" -H "X-Forwarded-Proto: ${PROTO:-https}" "$@" http://127.0.0.1:18083/; }
curl -s http://127.0.0.1:18081/ | grep -q 'id="locks"' && echo "ok   admin shows Locks card" || { echo "FAIL Locks card missing"; exit 1; }
expect "lock: create user"     "$(post -d 'action=lock-user-set&group=family&user=alice&password=integration-pw')" 303
grep -q 'integration-pw' "$STATE" && { echo "FAIL password stored in clear"; exit 1; } || echo "ok   only the hash is stored"
expect "lock: lock g.lan"      "$(post -d 'action=lock&host=g.lan&lock=family')" 303
expect "lock: asks for login"  "$(lcode)" 401
expect "lock: right password"  "$(lcode -u alice:integration-pw)" 418
expect "lock: wrong password"  "$(lcode -u alice:nope)" 401
expect "lock: plain HTTP refused" "$(PROTO=http lcode -u alice:integration-pw)" 403
expect "lock: LAN skips it"    "$(XFF=192.168.1.5 lcode)" 418
lcode -u alice:nope >/dev/null; lcode -u alice:nope >/dev/null
expect "lock: banned after 3 failures" "$(lcode -u alice:integration-pw)" 429
expect "lock: other address fine" "$(XFF=203.0.113.77 lcode -u alice:integration-pw)" 418
expect "lock: unlock g.lan"    "$(post -d 'action=lock&host=g.lan&lock=')" 303
expect "lock: open again"      "$(XFF=203.0.113.78 lcode)" 418
expect "private: set g.lan"    "$(post -d 'host=g.lan&mode=private')" 303
expect "private: outside refused" "$(XFF=203.0.113.79 lcode)" 403
expect "private: LAN passes"   "$(XFF=192.168.1.5 lcode)" 418
expect "private: back on"      "$(post -d 'host=g.lan&mode=on')" 303
for want in 'INF KILL-SWITCH: lock: user alice added to family' 'INF KILL-SWITCH: lock: g.lan locked with family' 'INF KILL-SWITCH: lock: 203.0.113.5 banned'; do
  grep -q "$want" "$RUN/traefik.log" && echo "ok   log: $want" || { echo "FAIL log missing: $want"; grep KILL-SWITCH "$RUN/traefik.log" | tail -5; exit 1; }
done
for want in 'INF KILL-SWITCH: geo: ES allowed until' 'INF KILL-SWITCH: geo: DE removed'; do
  grep -q "$want" "$RUN/traefik.log" && echo "ok   log: $want" || { echo "FAIL log missing: $want"; exit 1; }
done
for want in 'INF KILL-SWITCH: a.lan set to maint from 127.0.0.1' 'INF KILL-SWITCH: all sites set to block' \
  'INF KILL-SWITCH: schedule created for b.lan: block' 'INF KILL-SWITCH: schedule active since' 'INF KILL-SWITCH: schedule cancelled for b.lan'; do
  grep -q "$want" "$RUN/traefik.log" && echo "ok   log: $want" || { echo "FAIL log missing: $want"; grep KILL-SWITCH "$RUN/traefik.log"; exit 1; }
done
cat "$STATE"; echo
