# Async handlers

A handler can suspend while it waits for an event, then finish in a continuation on the same reactor thread. Other ready requests keep running. Ordinary handlers still return their responses directly.

`ctx.suspension.sleep()` schedules a timer. `ctx.suspension.wait()` provides the same lifecycle for an event source that completes a token. Neither starts a thread or blocks the reactor.

## A timer

```zig
const s = @import("swerver");
const Wait = struct { milliseconds: u32 };

fn delay(ctx: *s.router.HandlerContext) s.response.Response {
    const ms: u32 = 10;
    return ctx.suspension.sleep(ms, Wait, .{ .milliseconds = ms }, finished)
        catch return ctx.text(503, "wait unavailable");
}

fn finished(ctx: *s.suspension.ResumeContext) s.response.Response {
    const value = ctx.stash(Wait);
    const body = @import("std").fmt.bufPrint(
        ctx.response_buf, "{d}", .{value.milliseconds},
    ) catch unreachable;
    return ctx.text(200, body);
}
```

Return the response from `sleep()` immediately. The continuation receives a copy of the stash, an 8 KiB response buffer, and access to application state through `ctx.state(T)`. It can return a response or suspend again. A chain reuses the owned request metadata and releases its previous slot before reserving the next one.

Stashes must contain plain values, at most 256 bytes with alignment at most 16. Integers, enums, arrays, and structs of plain values work. Pointers and slices are rejected at compile time. Copy small request values into fixed arrays, or store application-owned data under an ID. Request buffers, handler contexts, and response scratch do not survive the callback that supplied them. Use the same stash type when scheduling and reading a continuation.

Timers use monotonic deadlines and never become ready before the requested delay. Delivery can be later under load. A zero-millisecond wait yields; it does not call the continuation inline. Each reactor turn delivers at most 256 ready continuations before returning to I/O.

## Completing an event

```zig
const pending = try ctx.suspension.wait(
    5_000, Job, job, finished, .{ .on_cancel = cancelled },
);
// Register pending.token with your reactor-owned event source.
return pending.response;
```

The event source calls `handle.complete(token)` on the owning reactor thread. Completion queues the continuation with `ctx.event == .ready`. If the deadline wins, the continuation gets `.timeout`. Duplicate, stale, or late completions return `false`. A token becomes stale when its wait is removed, including after connection reuse.

All suspension methods are reactor-thread-only. A saved handle may be used for `complete()` while its server remains alive; `sleep()` and `wait()` may only be called from the handler or continuation that received the handle. This API does not itself register sockets or dispatch work to a thread pool. An adapter must integrate its event source with the reactor. Hosts completing work from another thread should use the existing FFI completion interface.

`on_cancel` receives a `CancelContext` with the stash, application state, and cancellation reason. Use it to release application resources when a client disconnects, resets its stream, or the server shuts down. It runs once for that wait and cannot produce a response or schedule a new wait. Normal completion and timeout invoke the continuation instead; perform their cleanup there. If a handler schedules a wait but returns an ordinary response, Swerver cancels the unused wait as `.abandoned`.

## Bounds and lifecycle

- The registry allows `server.max_connections` pending waits **per worker**, shared across native HTTP/1.1, HTTP/2, and HTTP/3 handlers. HTTP/2 and HTTP/3 reserve one slot per waiting stream. Each request may have one pending native wait.
- The slab, indexed timer heap, and lookup maps allocate lazily on the first wait. Insertion, expiry, and cancellation take O(log n); closing a connection visits only its waits. Exhaustion returns `error.Full` to the handler.
- Each suspended request owns a snapshot for response filters, payment settlement, and middleware. It permits at most 64 KiB of copied byte data, 128 request headers, and 64 headers from each response-header source. Larger snapshots return `error.SnapshotTooLarge`; allocation failures return `error.OutOfMemory`.
- Pre-request middleware and the handler run once. The final response passes through the normal response filters, settlement, and post-response hooks, including the full wait in middleware elapsed time. HTTP/1 tracing retains the original span start.
- HTTP/1.1 preserves pipeline order while waiting. HTTP/2 and HTTP/3 suspend individual streams, allowing siblings to continue. Disconnects, stream resets, idle expiry, and shutdown release waits. Configured connection timeouts still apply and can cancel a wait before its own deadline.

The registry is separate from PostgreSQL, WASM, and FFI parks. Existing connection limits and buffer sizes stay at their configured values. A deployment still needs enough connection and response-buffer capacity for its workload. Suspending CPU-heavy work does not make that work asynchronous: every callback must return promptly.

## Run the example

```sh
zig build async-example -Denable-http2=true
./zig-out/bin/swerver-async-example
python3 examples/async/test.py
```

The example runs one worker and serves `/delay/:ms`, `/chain/:ms`, `/wait/:key/:ms`, `/complete/:key`, `/plain`, and `/stats`. It accepts the usual `--config` option; the test script accepts an optional port. Installing Python's `h2` package enables its HTTP/2 checks. The [example source](https://github.com/justinGrosvenor/swerver/blob/main/examples/async/main.zig) also demonstrates event completion and cancellation cleanup.
