# ladder-script.org deploy runbook

How to deploy and maintain the Ladder Script site at `ladder-script.org`.

The site lives on a single VM (SSH alias: `ladder-script`, IP
`85.9.213.194`). The same box runs the signet node and the
`ladder-proxy` Python service that backs `/api/ladder/*`, so the
nginx → proxy hop is over localhost.

## Prerequisites

- DNS: `ladder-script.org` and `www.ladder-script.org` A records
  point at `85.9.213.194`.
- SSH access: local `~/.ssh/config` has a `ladder-script` alias with
  passwordless sudo.
- The `ladder-proxy.service` is running on the VM and listening on
  port 8340 (verify with
  `ssh ladder-script sudo ss -tlnp 'sport = :8340'`).
- Run all commands below from the repo root.

## Routine deploy (most common)

```
./deploy/deploy-ladder-script.sh web
```

Rsyncs `tools/` to `/var/www/ladder-script/` with `--delete`,
mirrors `block-docs/` to both `block-docs/` and `docs/blocks/`
(the docs viewer expects both paths), and fixes ownership to
`www-data`. Browser-cache is bypassed by the `no-cache` header on
HTML, so changes are visible immediately.

Smoke-test:

```
./deploy/deploy-ladder-script.sh smoke
```

Hits `https://ladder-script.org/api/ladder/status` and checks for
HTTP 200 + a sane signet tip.

## First-time setup on a fresh VM

### 1. Open the firewall + install nginx

```
./deploy/deploy-ladder-script.sh prep
```

Idempotent. Opens TCP 80 and 443 in UFW (the box ships with a
default-deny policy — without this, every inbound HTTP request
times out at the firewall and the site looks broken even though
nginx is fine), then `apt install -y nginx`.

### 2. Install the vhost (HTTP only, no TLS yet)

```
./deploy/deploy-ladder-script.sh nginx
```

Copies `deploy/nginx-ladder-script.conf` to
`/etc/nginx/sites-available/ladder-script`, symlinks into
`sites-enabled/`, creates `/var/www/ladder-script`, runs
`nginx -t`, and reloads. At this point `http://ladder-script.org/`
serves a 404 from the empty webroot. The vhost is live on port 80
only.

### 3. Sync content

```
./deploy/deploy-ladder-script.sh web
```

(Same command as routine deploy.)

### 4. Issue TLS certificate

```
ssh ladder-script sudo apt install -y certbot python3-certbot-nginx
ssh ladder-script sudo certbot --nginx \
    -d ladder-script.org -d www.ladder-script.org
```

Certbot edits the vhost in place to add the `listen 443 ssl` block,
the certificate paths, and an HTTP → HTTPS redirect. Accept the
redirect option when prompted. Auto-renewal runs via the standard
systemd timer.

### 5. Install the proxy CORS drop-in

```
ssh ladder-script sudo mkdir -p /etc/systemd/system/ladder-proxy.service.d
cat deploy/ladder-proxy.service.d/cors.conf | \
    ssh ladder-script "sudo tee /etc/systemd/system/ladder-proxy.service.d/cors.conf"
ssh ladder-script "sudo systemctl daemon-reload && sudo systemctl restart ladder-proxy"
```

The proxy's default `ALLOWED_ORIGINS` does not include
`ladder-script.org` — without this drop-in, browsers loading the
site will silently fail every JS API call with a CORS error.

## Two non-obvious gotchas — preserve these

Both are baked into the current configs. Don't strip them without
understanding the failure mode:

1. **`limit_except GET POST OPTIONS` in the nginx `/api/ladder/`
   block.** OPTIONS is required so CORS preflight requests reach
   the proxy. Removing it returns 403 at the edge and breaks every
   browser POST, even though direct `curl` requests still succeed.
2. **`block-docs/` mirrored to two paths.** The standalone viewer
   loads from `/block-docs/`; the docs viewer fetches from
   `/docs/blocks/` via AJAX. Both copies must exist. The deploy
   script handles this; doing a manual `rsync` will miss it.

## Rollback

If something is broken and the site needs to come down fast:

```
ssh ladder-script sudo rm /etc/nginx/sites-enabled/ladder-script
ssh ladder-script sudo nginx -t
ssh ladder-script sudo systemctl reload nginx
```

DNS stays pointed at the VM but nginx returns the default vhost
(or 404) until the symlink is restored. No impact on the
`ladder-proxy.service` — the reverse proxy is gone, but the Python
service on port 8340 is still running.

## Tightening the proxy binding (future)

The `ladder-proxy` service still binds `0.0.0.0:8340` from when
`bitcoinghost.org` reverse-proxied to it over the public internet.
That path no longer exists — only nginx on this same box talks to
the proxy now. Switching uvicorn to `--host 127.0.0.1` removes an
unnecessary attack surface. Done as a separate change so its
blast radius is obvious if anything else turns out to depend on
the public binding.
