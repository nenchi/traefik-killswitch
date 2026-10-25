# Traefik Kill Switch

> **Beta.** Tested against Traefik v3.7. Feedback and issues welcome.

A Traefik middleware plugin that does nothing until you need it. When you need it, a web page lets you
switch any site, or all of them at once, to:

| Mode    | Visitors get                                   |
|---------|------------------------------------------------|
| `on`    | the site, untouched (default)                  |
| `maint` | `503` + a maintenance page (yours or built-in) |
| `block` | `403 Forbidden`, the backend is never reached  |

Use it when a vulnerable app has to come off the internet *now*. You click a button and it's done:
there's no config edit, no container restart and no Traefik reload. A switch takes effect within one second.

## How it works

- Attach the middleware to an entry point (or to individual routers). Each request is checked against
  its `Host` in a small JSON state file.
- A second instance of the same plugin, with `admin: true`, serves the web page on a router of its own
  and writes the state file.
- `*` is the global switch. If it isn't `on`, it overrides every per-host setting.
- If the state file is missing, everything is `on`. If it becomes unreadable or corrupt, the last good
  state is kept, so a broken file can't silently reopen a blocked site.

## Setup

### 1. Load the plugin

From the plugin catalog (static config):

```yaml
experimental:
  plugins:
    killswitch:
      moduleName: github.com/nenchi/traefik-killswitch
      version: v0.1.0
```

Or as a local plugin, e.g. while testing a fork. Mount the repo at
`/plugins-local/src/github.com/nenchi/traefik-killswitch` in the Traefik container, then:

```yaml
experimental:
  localPlugins:
    killswitch:
      moduleName: github.com/nenchi/traefik-killswitch
```

### 2. Give Traefik a writable directory for the state

```yaml
# docker compose, traefik service
volumes:
  - ./killswitch:/data
```

### 3. Gate the sites and add the admin page (dynamic config)

```yaml
http:
  middlewares:
    killswitch:
      plugin:
        killswitch:
          stateFile: /data/killswitch.json
          # maintenanceFile: /data/maintenance.html   # optional custom page
          excludeHosts:                 # never gated, so "*" can't lock you out
            - killswitch.example.com
            - auth.example.com          # your SSO login page, if it's on the same entry point
    killswitch-admin:
      plugin:
        killswitch:
          stateFile: /data/killswitch.json
          admin: true

  routers:
    killswitch-admin:
      rule: Host(`killswitch.example.com`)
      entryPoints: [websecure]      # fine when its host is in excludeHosts
      middlewares: [your-auth, killswitch-admin]
      service: noop@internal
```

To gate every site at once, add the middleware to the entry point (static config):

```yaml
entryPoints:
  websecure:
    address: ":443"
    http:
      middlewares: [killswitch@file]
```

Or add it to individual routers, e.g. with the Docker label
`traefik.http.routers.myapp.middlewares=killswitch@file`.

## Options

| Option            | Default                 | Description                                                         |
|-------------------|-------------------------|---------------------------------------------------------------------|
| `stateFile`       | `/data/killswitch.json` | Shared JSON state. Must be writable for the admin instance.         |
| `admin`           | `false`                 | Serve the web page instead of gating. Never forwards to a backend.  |
| `maintenanceFile` | built-in page           | HTML served with `503` in `maint` mode. Read once at startup.       |
| `excludeHosts`    | none                    | Hosts that are never gated: the admin page and your auth provider.  |

You can also edit the state file by hand or from a script:

```json
{ "*": "on", "app.example.com": "maint", "old.example.com": "block" }
```

## Custom maintenance page

Start from [`examples/maintenance.html`](examples/maintenance.html): copy it next to the state file
(e.g. `/data/maintenance.html`), edit the text, and set `maintenanceFile: /data/maintenance.html`.

- **Keep it one self-contained file.** While a site is in maintenance, every request to it returns this
  page, including requests for its CSS, images and fonts. Inline your styles, and use inline SVG or `data:` URIs for images.
- Traefik reads the file at startup, so restart Traefik after editing it.

## Security

- **Put authentication in front of the admin router** (forwardAuth, Authelia, Authentik, basicAuth, an IP
  allowlist). Anyone who can reach the page can take your sites down.
- If the admin page or your SSO login runs on an entry point the kill switch gates, put their hosts in
  `excludeHosts`. Otherwise setting `*` to `block` locks you out of the switch, and you'd have to
  edit the file by hand.
- Cross-site form posts are rejected (`Origin` / `Sec-Fetch-Site` checks).

## Limitations

- The admin page lists hosts that are already in the state file, plus hosts seen since Traefik started.
  You can add any other host with the form.
- Matching is by exact host name. There are no wildcards or path rules.

## Development

```sh
go test -race ./...
yaegi test .                         # Traefik's interpreter; catches bugs plain Go doesn't
TRAEFIK=/path/to/traefik test/integration.sh   # end-to-end against a real Traefik binary
```

The Yaegi interpreter mishandles tuple assignments that include `nil` or struct fields
(`a.x, a.y = 1, 2`), so the code uses separate statements on purpose. Keep it that way.

## License

MIT
