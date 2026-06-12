# CLI flags

The `swerver` binary takes a small set of flags. Everything else lives in the [config file](config-schema.md); the CLI is for picking a config and overriding the handful of values you most often change per-deployment.

```bash
swerver --config config.json --workers 8
```

Each flag accepts both `--flag value` and `--flag=value` forms.

## Flags

| Flag | Argument | Description |
| --- | --- | --- |
| `--config <path>` | file path | Load a JSON [config file](config-schema.md). Mutually exclusive with `--config-url`. |
| `--config-url <url>` | URL | Fetch the JSON config over HTTP(S) at startup instead of from disk. Mutually exclusive with `--config`. |
| `--config-cache <path>` | file path | With `--config-url`, write the fetched config here and fall back to it if a later fetch fails. |
| `--config-header <h>` | `Name: value` | Extra request header for `--config-url` (repeatable). Also seeded from `SWERVER_CONFIG_HEADERS`. |
| `--workers <n>` | integer | Number of worker processes. Overrides `server.workers`. `1` runs single-process (no fork); `0` auto-detects the CPU count. |
| `--static-root <path>` | directory | Serve static files from this directory. Overrides `server.static_root`. |
| `--cert <path>` | file path | PEM certificate for TLS. Overrides `tls.cert_path`. |
| `--key <path>` | file path | PEM private key for TLS. Overrides `tls.key_path`. |
| `--run-for-ms <ms>` | integer | Run for the given number of milliseconds, then exit. Intended for tests and benchmarks. |

!!! note "CLI overrides win"
    When a flag and the config file set the same value (`--workers`, `--static-root`, `--cert`, `--key`), the CLI value wins. Run with no flags at all and swerver starts on `0.0.0.0:8080` with built-in defaults.

!!! tip "Config token"
    For `--config-url`, set `SWERVER_CONFIG_TOKEN` in the environment to send a bearer token with the fetch, keeping secrets out of the process arguments.

## Related

- [Build options](build-options.md): the `-D` flags that decide which protocols are compiled in.
- [Config schema](config-schema.md): the full JSON config reference.
