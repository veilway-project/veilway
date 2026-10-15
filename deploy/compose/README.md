# Veilway with Docker Compose

This runs the node and the panel together on one host. The panel reaches the node's control API through a shared volume that holds the socket. The panel listens on `127.0.0.1` only, so a web server on the host must serve it over TLS.

You need Docker Engine with the Compose plugin.

## 1. Write the node config

Copy `config.example.json` to `config.json` and edit it as the main README says. Two changes for the container:

- The `ws` transport listens on port 8443, not 443. A non-root process cannot bind a port below 1024. `docker-compose.yml` publishes 443 on the host to 8443 in the container.
- Its certificate files go in a `tls` folder next to `config.json`.

Make the keys with:

```
docker compose run --rm --no-deps --entrypoint veilway node genkey
```

## 2. Copy the files into the volumes

The image runs as uid 65532, so the files in its volume must belong to that user. The config must not be readable by anyone else.

```
docker run --rm -v veilway-node-config:/etc/veilway -v "$PWD":/in alpine sh -c 'cp /in/config.json /etc/veilway/ && cp -r /in/tls /etc/veilway/ && chown -R 65532:65532 /etc/veilway && chmod -R go-rwx /etc/veilway'
```

Leave out `cp -r /in/tls` if you do not use the `ws` transport.

## 3. Start the node

```
docker compose up -d node
docker compose logs node
```

The log shows the node's public key. Check the config with:

```
docker compose exec node veilway check --config /etc/veilway/config.json
```

## 4. Write the panel config

Save this as `panel.json`. Replace the prefix with a random path, for example the output of `echo "/$(openssl rand -hex 16)"`.

```json
{
  "prefix": "/replace-with-random-path",
  "listen": "127.0.0.1:8480",
  "database": "/var/lib/veilway-panel/panel.db",
  "keys": "/var/lib/veilway-panel/panel.keys",
  "signing": "/var/lib/veilway-panel/signing.keys",
  "node_socket": "/run/veilway/veilway.sock",
  "trusted_proxies": ["127.0.0.1"]
}
```

Copy it into the panel's volume:

```
docker run --rm -v veilway-panel-config:/etc/veilway-panel -v "$PWD":/in alpine sh -c 'cp /in/panel.json /etc/veilway-panel/ && chown -R 65532:65532 /etc/veilway-panel'
```

## 5. Start the panel and put a web server in front

```
docker compose up -d
```

The panel answers on `127.0.0.1:8480` on the host. Point nginx or Caddy at it with TLS, and list the web server's address in `trusted_proxies` if it is not `127.0.0.1`. The panel README covers the `not_found` setting.

`docker compose ps` shows the panel as `healthy` once port 8480 accepts connections.

## Updates

```
docker compose pull
docker compose up -d
```

## Notes

- Keep the volumes when you stop the stack. `docker compose down -v` deletes the keys and the usage state.
- An `l3` exit needs the node to run as root with NET_ADMIN and the TUN device. Add these lines under `node` in `docker-compose.yml`:

  ```yaml
      user: "0"
      cap_add: [NET_ADMIN]
      devices: ["/dev/net/tun"]
  ```

  Netstack exits need none of this.
- A WireGuard UDP port in the config needs its own line under `ports`. The example config uses 51820, 51821 and 51822.
