# Running from a config file

You don't have to embed swerver to use it. The prebuilt `swerver` binary reads a JSON config file and runs as a standalone server, reverse proxy, or API gateway: no Zig code, no recompile. This is the right path when you want static file serving, TLS termination, or a reverse proxy without writing handlers.

## Run it

```bash
swerver --config config.json
```

(From a source checkout, `zig build run -- --config config.json`.)

## A minimal config

```json
{
  "server": {
    "port": 8080,
    "workers": 0,
    "static_root": "./public"
  }
}
```

This serves files from `./public` on `0.0.0.0:8080`, one worker process per CPU core.

| Field | Meaning |
| --- | --- |
| `server.port` | TCP port to listen on (default `8080`). |
| `server.workers` | Worker processes to fork. `0` means **one per CPU core**. |
| `server.static_root` | Directory to serve static files from. Omit to disable static serving. |

!!! note "`workers: 0` = one per CPU"
    Workers are separate processes that share the listening socket via `SO_REUSEPORT`, each running its own single-threaded event loop. Setting `workers` to `0` (or omitting it) forks one per available core. Set an explicit number to cap it.

A few flags can also be passed directly on the command line and override the config: `--workers <n>` and `--static-root <path>`. See [CLI flags](../reference/cli.md) for the full list.

## Hot reload

swerver reloads value-type config fields on `SIGHUP` without dropping connections: timeouts, limits, and similar scalar settings are re-read in place.

```bash
kill -HUP $(pgrep -f swerver)
```

This lets you retune a running server (and, with the gateway config, swap routes and upstreams) without a restart.

## Beyond the minimum

A real config also has `timeouts`, `limits`, `buffer_pool`, `tls`, `quic`, `upstreams`, and `routes` blocks: that's how you turn the binary into a TLS terminator, reverse proxy, or full API gateway. Those aren't covered here.

- **[Configuration guide](../guide/configuration.md)**: a walkthrough of every block with worked examples.
- **[Config schema reference](../reference/config-schema.md)**: the complete field list, types, and defaults.

Prefer to wire routes in Zig instead? See [Your first server](first-server.md).
