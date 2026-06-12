# PostgreSQL

swerver ships a **native, async PostgreSQL client** (wire protocol v3, SCRAM-SHA-256 auth, optional TLS) written in Zig with no libpq dependency. It lets a handler serve data straight from the database, turning the gateway into an app server with no sidecar process.

The defining property is that **a query never blocks the reactor**. A handler issues a query and *parks*: the connection is suspended, the worker goes back to serving other requests, and a *continuation* runs when the rows arrive. A slow or unreachable database stalls only the requests waiting on it, never the rest of the worker.

!!! info "Reached only when configured"
    The client is wired up only when a `postgres` config block is present. Without it, `ctx.pg.query(...)` returns `error.NotConnected`.

## Configuration

The pool is configured under the top-level `postgres` key:

```json
{
  "postgres": {
    "url": "postgres://app@db.internal:5432/appdb?sslmode=verify-full",
    "password_env": "PG_PASSWORD",
    "pool_size_per_worker": 2,
    "statement_timeout_ms": 5000,
    "ssl_root_cert": "/etc/ssl/rds-ca.pem"
  }
}
```

| Field | Default | Description |
| --- | --- | --- |
| `url` | none | Connection URL: `postgres://user@host:port/db?sslmode=...` |
| `password_env` | none | Name of the **env var** holding the password (see below) |
| `pool_size_per_worker` | `2` | Connections per worker, must be `1` to `4` |
| `statement_timeout_ms` | `5000` | Per-op deadline; bounds how long a parked request waits |
| `ssl_root_cert` | system trust | CA bundle (PEM) for `sslmode=verify-full` |

!!! warning "The password never lives in the config file"
    swerver reads the password from the env var named by `password_env`, and **ignores any password embedded in the `url`** (it logs a warning if it finds one). The config file is served by the admin API, so secrets must stay out of it.

`sslmode` is set in the URL query string: `disable`, `require`, or `verify-full` (the default when TLS is on, doing chain + hostname verification). `pool_size_per_worker` outside `1` to `4` is rejected at startup with `error.InvalidPostgresConfig`.

Each worker is a separate process and keeps its own pool; there is no cross-worker sharing.

## The handler API

The query surface hangs off the handler context as `ctx.pg`. A query is a single expression that issues the SQL, registers a continuation, and parks:

```zig
ctx.pg.query(sql, args, StashType, stash_init, continuationFn)
```

| Argument | Type | Description |
| --- | --- | --- |
| `sql` | `[]const u8` | Parameterized SQL with `$1`, `$2`, … placeholders |
| `args` | `[]const ?[]const u8` | Text-format parameters; `null` is SQL `NULL` |
| `StashType` | `type` | A plain-data struct carrying state into the continuation |
| `stash_init` | `StashType` | Initial stash value (copied into park state) |
| `continuationFn` | `*const fn (*ResumeContext) Response` | Runs when rows arrive |

`query()` returns the parked `Response` itself, a sentinel the router intercepts. You cannot "forget to park": the only value that parks the connection *is* the return value. Synchronous failures (pool down, op queue full) surface as ordinary errors you map to a 503 while you still hold the request:

```zig
return ctx.pg.query(sql, &.{org}, Stash, .{ .org_id = 7 }, onRows)
    catch return ctx.text(503, "database unavailable");
```

The `QueryError` set: `NotConnected`, `QueueFull`, `AlreadyParked`, `ParkTableFull`, `RequestTooLarge`.

### The stash

Anything the continuation needs from phase 1 must be copied into the **stash**, because the read buffer (and so `ctx.request`) is recycled while parked. The stash is comptime-checked to be plain data: a pointer or slice field is a compile error. Copy bytes into fixed arrays.

```zig
const Stash = struct {
    org_id: u64,
    name_buf: [64]u8 = undefined, // copied bytes: a slice would not compile
    name_len: u8 = 0,
    step: u8 = 0,
};
```

The stash is capped at 256 bytes.

### The continuation

The continuation receives a `*ResumeContext`, deliberately **not** a `HandlerContext`. It has fresh `response_buf`, response headers, and an arena, but **no `request` field**: reading the recycled request is made unrepresentable rather than merely discouraged.

It runs **exactly once**, delivering either rows or an error through `rctx.result` (`PgError`: `Timeout`, `ConnectionLost`, `PipelineAborted`, `ServerError`, `ResultTooLarge`). Iterate rows with `res.rows()`, read columns by index, and serialize into the response before returning, because the row data borrows the connection's recv buffer and is valid only for the duration of the call.

| Column accessor | Returns |
| --- | --- |
| `row.int2(i)` / `row.int4(i)` / `row.int8(i)` | `i16` / `i32` / `i64` |
| `row.float8(i)` | `f64` |
| `row.boolean(i)` | `bool` |
| `row.text(i)` | `[]const u8` (also varchar / numeric-as-text) |
| `row.textOpt(i)` | `?[]const u8` (SQL `NULL` → `null`) |
| `row.col(i)` | raw `DataValue` (`null` for SQL `NULL`) |

## A complete example

A `GET /orgs/:org/users` handler that runs a `SELECT` and returns JSON:

```zig
const std = @import("std");
const swerver = @import("swerver");
const pg = swerver.db.pg.handler_api; // ResumeContext, Row, etc.

const Stash = struct { org_id: u64 = 0 };

fn listUsers(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    const org = ctx.getParam("org") orelse return ctx.text(400, "missing org");

    return ctx.pg.query(
        "select id, name from users where org_id = $1 order by id",
        &.{org}, // text-format param: $1
        Stash,
        .{ .org_id = 0 },
        onUsers,
    ) catch return ctx.text(503, "database unavailable");
}

const User = struct { id: i64, name: []const u8 };

fn onUsers(rctx: *pg.ResumeContext) swerver.response.Response {
    const res = rctx.result catch |err| switch (err) {
        error.Timeout => return rctx_text(rctx, 504, "query timed out"),
        else => return rctx_text(rctx, 502, "database error"),
    };

    var users = std.ArrayList(User){};
    var it = res.rows();
    while (it.next()) |row| {
        const id = row.int8(0) catch return rctx_text(rctx, 500, "decode error");
        const name = row.text(1) catch return rctx_text(rctx, 500, "decode error");
        users.append(rctx.allocator(), .{ .id = id, .name = name }) catch break;
    }

    // Serialize into the resume buffer before returning: rows borrow the
    // recv buffer and die when this continuation returns.
    const body = std.json.Stringify.valueAlloc(rctx.allocator(), users.items, .{}) catch
        return rctx_text(rctx, 500, "encode error");
    return .{ .status = 200, .body = .{ .bytes = body } };
}

fn rctx_text(rctx: *pg.ResumeContext, status: u16, msg: []const u8) swerver.response.Response {
    _ = rctx;
    return .{ .status = status, .body = .{ .bytes = msg } };
}
```

!!! tip "Chaining queries"
    A continuation can itself issue the next query with `rctx.query(...)` (or `rctx.queryBatch(...)`) and re-park through the same machinery. The blessed pattern for a multi-step flow is a single continuation function that switches on a `step` field in the stash. It reads like a state machine because it is one.

## Going deeper

This page covers the handler surface. For the wire protocol, the connection state machine, pipelining, TLS client mode, and the memory model, see `docs/design/9.0-postgres-client.md` in the repo.
