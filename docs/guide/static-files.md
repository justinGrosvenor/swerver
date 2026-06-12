# Static files

Point `server.static_root` at a directory and swerver serves files from it for any request path **not matched by a registered route or a proxy rule**. Routes and the reverse proxy take precedence; static serving is the fallback.


```json
{
  "server": {
    "static_root": "./public"
  }
}
```

Empty (the default) disables static serving entirely. The path is validated at startup: it may not contain null bytes or `..` traversal segments.

## Zero-copy delivery

File responses go out through `sendfile(2)`, so file bytes move from the page cache to the socket without passing through a userspace buffer or the buffer pool. The OS handles the copy; swerver only schedules it and tracks completion against the connection's write budget (file I/O counts toward write backpressure, and reads pause if the write side fills).

## Precompressed siblings

If a precompressed sibling of the requested file exists next to it and the client's `Accept-Encoding` permits that encoding, swerver serves the compressed file directly. This is **always on** (there's no flag) and it falls back to the identity file when no acceptable sibling exists.

Given a request for `app.js`, swerver looks for, in order:

1. `app.js.br`: served with `Content-Encoding: br` when `br` is acceptable.
2. `app.js.gz`: served with `Content-Encoding: gzip` when `gzip` is acceptable.
3. `app.js`: the identity file.

An encoding is "acceptable" when its token is present in `Accept-Encoding` and not disabled with `q=0`. When a compressed sibling is served:

- The `Content-Type` is derived from the **original** path (`app.js` → JavaScript), never the `.br`/`.gz` suffix.
- A `Vary: Accept-Encoding` header is added so caches key on the negotiated encoding.

Precompress your assets at build time (for example `brotli -k app.js` and `gzip -k app.js`) and drop the siblings alongside the originals.

## In-memory cache

For hot static assets, set `cache_static_files: true`:

```json
{
  "server": {
    "static_root": "./public",
    "cache_static_files": true
  }
}
```

On first serve, swerver caches the file body in memory, **keyed by path and negotiated encoding** (identity / br / gzip), so subsequent hits skip the `open` / `fstat` / `sendfile` syscalls and serve straight from memory. The cache is:

- **Per worker**, lazily populated on first access, and bounded.
- **Encoding-aware**: the identity, `.br`, and `.gz` variants of a path are cached as separate entries.
- **Fresh on `Date`**: the `Date` header (and `Content-Length`, and HEAD handling) come from the normal response path at send time, never baked into the cached bytes.

Caching trades memory for fewer syscalls; leave it off when `static_root` holds many large or rarely-requested files.

!!! note "Conditional requests & ranges"
    Responses carry `Last-Modified`/`ETag` metadata to support conditional requests, and single-range requests are honored within `max_body_bytes`. See the file-I/O design notes for the full matrix.
