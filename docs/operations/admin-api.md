# Admin API

The admin API is a runtime management interface for editing routes and upstreams **without restarting** the server. It listens on its own port, separate from the main traffic listener, and authenticates every request with an API key.

This is the path for changes the [SIGHUP reload](deployment.md#graceful-shutdown-config-reload) can't do live: hot reload updates value-type fields in place but treats route and upstream changes as structural. The admin API applies them at runtime.

## Enabling it

Add an `admin` block to the config:

```json
{
  "admin": {
    "enabled": true,
    "port": 9090,
    "address": "127.0.0.1",
    "api_key": "secret-admin-key"
  }
}
```

| Field | Default | Description |
| --- | --- | --- |
| `enabled` | `false` | Start the admin listener |
| `port` | `9180` | Port for the admin listener (separate from traffic) |
| `address` | `127.0.0.1` | Bind address; keep it on a private interface |
| `api_key` | (none) | Required on every request |

!!! warning "Lock it down"
    The admin API can rewrite routing at runtime. Bind it to a private interface or loopback (`address`), never the public one, and treat `api_key` as a secret. The config file is served by this API, so it must not contain other secrets (PostgreSQL passwords go in `password_env`, not the file).

## Authentication

Send the API key on every request. The key is matched against `admin.api_key`:

```sh
curl -H "X-API-Key: secret-admin-key" http://127.0.0.1:9090/routes
```

## Endpoints

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/routes` | List current routes |
| `POST` | `/routes` | Add a route |
| `DELETE` | `/routes/{prefix}` | Remove the route with that path prefix |
| `GET` | `/upstreams` | List upstreams |
| `POST` | `/upstreams` | Add an upstream |
| `PUT` | `/upstreams/{name}` | Update an upstream |
| `DELETE` | `/upstreams/{name}` | Remove an upstream |

The JSON bodies match the `routes[]` and `upstreams[]` shapes from the config file. See [Reverse proxy & gateway](../guide/reverse-proxy.md) for the field reference.

## Examples

List routes:

```sh
curl -H "X-API-Key: secret-admin-key" http://127.0.0.1:9090/routes
```

Add an upstream:

```sh
curl -X POST http://127.0.0.1:9090/upstreams \
  -H "X-API-Key: secret-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
        "name": "api_canary",
        "servers": [ { "address": "10.0.0.9", "port": 8080 } ],
        "load_balancer": "round_robin"
      }'
```

Add a route pointing at it:

```sh
curl -X POST http://127.0.0.1:9090/routes \
  -H "X-API-Key: secret-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
        "path_prefix": "/canary/",
        "upstream": "api_canary",
        "rewrite_pattern": "/canary/",
        "rewrite_replacement": "/"
      }'
```

Remove a route by its prefix:

```sh
curl -X DELETE http://127.0.0.1:9090/routes/%2Fcanary%2F \
  -H "X-API-Key: secret-admin-key"
```

## See also

- [Reverse proxy & gateway](../guide/reverse-proxy.md): route and upstream field reference.
- [Deployment](deployment.md): SIGHUP reload vs. runtime edits.
