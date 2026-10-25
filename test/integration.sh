#!/usr/bin/env bash
# Runs a real Traefik with this plugin loaded via localPlugins (Yaegi) and checks the switch end to end.
# Usage: TRAEFIK=/path/to/traefik test/integration.sh
set -euo pipefail
cd "$(dirname "$0")/.."
TRAEFIK=${TRAEFIK:-traefik}
RUN=test/run
rm -rf "$RUN" && mkdir -p "$RUN/plugins-local/src/github.com/nenchi/traefik-killswitch"
cp go.mod .traefik.yml killswitch.go "$RUN/plugins-local/src/github.com/nenchi/traefik-killswitch/"
STATE="$PWD/$RUN/state.json"
mkdir -p "$RUN/pages" && echo "default-page" > "$RUN/pages/maintenance.html" && echo "downtime-page" > "$RUN/pages/downtime.html"

cat > "$RUN/static.yml" <<YML
entryPoints:
  web:
    address: "127.0.0.1:18080"
    http:
      middlewares: [gate@file]
  admin:
    address: "127.0.0.1:18081"
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
          excludeHosts: [ks.lan]
    ks-admin:
      plugin:
        killswitch:
          stateFile: $STATE
          admin: true
  routers:
    a:
      entryPoints: [web]
      rule: Host(\`a.lan\`)
      service: noop@internal
    b:
      entryPoints: [web]
      rule: Host(\`b.lan\`)
      service: noop@internal
    admin-gated-ep:
      entryPoints: [web]
      rule: Host(\`ks.lan\`)
      middlewares: [ks-admin]
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
expect "b still passes"      "$(code_within b.lan 418)" 418
expect "set *=block"         "$(set_mode '*' block)" 303
expect "b blocked by global" "$(code_within b.lan 403)" 403
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
expect "cancel b window"     "$(post -d "host=b.lan&action=unschedule")" 303
expect "b passes again"      "$(code_within b.lan 418)" 418
FROM=$(date -d '+1 hour' +%Y-%m-%dT%H:%M); TO=$(date -d '+2 hour' +%Y-%m-%dT%H:%M)
expect "schedule b later"    "$(post -d "host=b.lan&action=schedule&mode=maint&from=$FROM&to=$TO")" 303
expect "b passes before window" "$(code_within b.lan 418)" 418
PAGE=$(curl -s http://127.0.0.1:18081/)
echo "$PAGE" | grep -q '(upcoming)' && echo "ok   admin shows upcoming window" || { echo "FAIL upcoming window not shown"; exit 1; }
echo "$PAGE" | grep -q 'value="b.lan"' && echo "ok   admin lists seen host b.lan" || { echo "FAIL admin does not list seen host"; exit 1; }
echo "$PAGE" | grep -q '<li>ks.lan</li>' && echo "ok   admin lists excluded host ks.lan as always on" || { echo "FAIL excluded host not shown"; exit 1; }
cat "$STATE"; echo
