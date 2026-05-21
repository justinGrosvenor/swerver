const std = @import("std");
const request = @import("../protocol/request.zig");
const response = @import("../response/response.zig");
const middleware = @import("middleware.zig");
const clock = @import("../runtime/clock.zig");

/// Rate Limiting Middleware
///
/// Implements token bucket rate limiting per IP address.
/// Zero heap allocations using fixed-size bucket storage.

const SpinMutex = struct {
    state: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),

    fn lock(self: *SpinMutex) void {
        while (self.state.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {}
    }

    fn unlock(self: *SpinMutex) void {
        self.state.store(0, .release);
    }
};

/// Maximum number of tracked IPs
const MAX_TRACKED_IPS = 4096;

/// Token bucket for rate limiting
pub const TokenBucket = struct {
    /// Current tokens available
    tokens: u32,
    /// Maximum tokens (bucket size)
    max_tokens: u32,
    /// Tokens added per second
    refill_rate: u32,
    /// Last refill timestamp (nanoseconds)
    last_refill_ns: i128,

    pub fn init(max_tokens: u32, refill_rate: u32) TokenBucket {
        return .{
            .tokens = max_tokens,
            .max_tokens = max_tokens,
            .refill_rate = refill_rate,
            .last_refill_ns = clock.realtimeNanos() orelse 0,
        };
    }

    /// Try to consume tokens, returns true if successful
    pub fn tryConsume(self: *TokenBucket, count: u32) bool {
        self.refill();

        if (self.tokens >= count) {
            self.tokens -= count;
            return true;
        }
        return false;
    }

    /// Refill tokens based on elapsed time
    fn refill(self: *TokenBucket) void {
        const now = clock.realtimeNanos() orelse return;
        const elapsed_ns = now - self.last_refill_ns;

        if (elapsed_ns <= 0) return;

        // Calculate tokens to add (tokens per nanosecond * elapsed)
        const elapsed_s: u64 = @intCast(@divFloor(elapsed_ns, std.time.ns_per_s));
        const new_tokens: u64 = elapsed_s * self.refill_rate;

        if (new_tokens > 0) {
            self.tokens = @min(self.max_tokens, self.tokens + @as(u32, @intCast(@min(new_tokens, std.math.maxInt(u32)))));
            self.last_refill_ns = now;
        }
    }

    /// Get time until next token is available (in milliseconds)
    pub fn timeUntilToken(self: *const TokenBucket) u64 {
        if (self.tokens > 0) return 0;
        if (self.refill_rate == 0) return std.math.maxInt(u64);

        // Time for one token = 1 second / refill_rate
        return 1000 / self.refill_rate;
    }
};

/// IP address key for bucket lookup — supports both IPv4 and full IPv6
pub const IpKey = struct {
    /// Full address bytes (4 for IPv4, 16 for IPv6)
    addr: [16]u8,
    len: u8,

    pub fn fromIpv4(ip: [4]u8) IpKey {
        var key = IpKey{ .addr = undefined, .len = 4 };
        @memcpy(key.addr[0..4], &ip);
        @memset(key.addr[4..], 0);
        return key;
    }

    pub fn fromIpv6(ip: [16]u8) IpKey {
        return .{ .addr = ip, .len = 16 };
    }

    pub fn hash(self: IpKey) u64 {
        return std.hash.Wyhash.hash(0, self.addr[0..self.len]);
    }

    pub fn eql(a: IpKey, b: IpKey) bool {
        return a.len == b.len and std.mem.eql(u8, a.addr[0..a.len], b.addr[0..b.len]);
    }
};

/// Per-IP bucket entry
const BucketEntry = struct {
    key: IpKey,
    bucket: TokenBucket,
    /// Last access time for LRU eviction
    last_access_ns: i128,
    /// Is this entry in use?
    active: bool,
};

/// Rate limiter with fixed-size bucket storage.
/// Thread-safe via mutex for concurrent access from multiple event loops.
pub const RateLimiter = struct {
    /// Bucket entries (fixed size, LRU eviction)
    entries: [MAX_TRACKED_IPS]BucketEntry,
    /// Number of active entries
    count: usize,
    /// Configuration
    config: Config,
    mutex: SpinMutex = .{},

    pub const Config = struct {
        /// Maximum requests per second per IP
        requests_per_second: u32 = 100,
        /// Burst size (bucket capacity)
        burst_size: u32 = 200,
        /// Enable rate limiting
        enabled: bool = true,
        /// Paths to exclude from rate limiting
        exclude_paths: []const []const u8 = &.{ "/.healthz", "/.ready", "/metrics" },
        /// Weight multiplier for premium routes (x402)
        premium_weight: u32 = 1,
    };

    pub fn init(config: Config) RateLimiter {
        // 4096 entries × a loop body with memory writes exceeds the default
        // comptime backward-branch quota when this runs during module-level
        // initialization of `var limiter`. Bump the quota so the comptime
        // eval of a no-op "mark every entry inactive" loop succeeds.
        @setEvalBranchQuota(MAX_TRACKED_IPS * 8);
        var rl = RateLimiter{
            .entries = undefined,
            .count = 0,
            .config = config,
        };

        for (&rl.entries) |*entry| {
            entry.active = false;
        }

        return rl;
    }

    /// Check if request is allowed, returns true if allowed
    pub fn check(self: *RateLimiter, ip: IpKey) bool {
        if (!self.config.enabled) return true;

        self.mutex.lock();
        defer self.mutex.unlock();
        const entry = self.getOrCreateBucket(ip);
        return entry.bucket.tryConsume(1);
    }

    /// Check with custom weight (for premium routes)
    pub fn checkWeighted(self: *RateLimiter, ip: IpKey, weight: u32) bool {
        if (!self.config.enabled) return true;

        self.mutex.lock();
        defer self.mutex.unlock();
        const entry = self.getOrCreateBucket(ip);
        return entry.bucket.tryConsume(weight);
    }

    fn getOrCreateBucket(self: *RateLimiter, ip: IpKey) *BucketEntry {
        const now = clock.realtimeNanos() orelse 0;

        // Look for existing entry
        for (&self.entries) |*entry| {
            if (entry.active and entry.key.eql(ip)) {
                entry.last_access_ns = now;
                return entry;
            }
        }

        // Find empty slot or evict LRU
        var target: *BucketEntry = &self.entries[0];
        var oldest_ns: i128 = std.math.maxInt(i128);

        for (&self.entries) |*entry| {
            if (!entry.active) {
                target = entry;
                break;
            }
            if (entry.last_access_ns < oldest_ns) {
                oldest_ns = entry.last_access_ns;
                target = entry;
            }
        }

        // Check if we're using an empty slot (increment count)
        const was_inactive = !target.active;

        // Initialize new entry
        target.* = .{
            .key = ip,
            .bucket = TokenBucket.init(self.config.burst_size, self.config.requests_per_second),
            .last_access_ns = now,
            .active = true,
        };

        if (was_inactive) {
            self.count += 1;
        }

        return target;
    }

    pub const RateLimitInfo = struct {
        retry_after_s: u64,
        resume_ms: u64,
    };

    pub fn checkAndGetInfo(self: *RateLimiter, ip: IpKey) ?RateLimitInfo {
        if (!self.config.enabled) return null;

        self.mutex.lock();
        defer self.mutex.unlock();
        const entry = self.getOrCreateBucket(ip);
        if (entry.bucket.tryConsume(1)) return null;
        const ms = entry.bucket.timeUntilToken();
        return .{
            .retry_after_s = (ms + 999) / 1000,
            .resume_ms = ms,
        };
    }

    /// Get retry-after header value in seconds
    pub fn getRetryAfter(self: *RateLimiter, ip: IpKey) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (&self.entries) |*entry| {
            if (entry.active and entry.key.eql(ip)) {
                return (entry.bucket.timeUntilToken() + 999) / 1000;
            }
        }
        return 1;
    }

    /// Get time until next token is available in milliseconds (for backpressure)
    pub fn getTimeUntilToken(self: *RateLimiter, ip: IpKey) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (&self.entries) |*entry| {
            if (entry.active and entry.key.eql(ip)) {
                return entry.bucket.timeUntilToken();
            }
        }
        return 1000;
    }
};

// ── Per-consumer / per-route rate limiting ─────────────────────

pub const RouteRateLimit = struct {
    requests_per_second: u32 = 100,
    burst_size: u32 = 200,
    key: KeyType = .consumer,

    pub const KeyType = enum { ip, consumer };
};

const MAX_CONSUMER_BUCKETS = 4096;

const ConsumerKey = struct {
    hash_val: u64,

    pub fn fromName(name: []const u8) ConsumerKey {
        return .{ .hash_val = std.hash.Wyhash.hash(0, name) };
    }

    pub fn fromIp(ip: IpKey) ConsumerKey {
        return .{ .hash_val = ip.hash() };
    }

    pub fn eql(a: ConsumerKey, b: ConsumerKey) bool {
        return a.hash_val == b.hash_val;
    }
};

const ConsumerBucketEntry = struct {
    key: ConsumerKey,
    bucket: TokenBucket,
    last_access_ns: i128,
    active: bool,
};

pub const ConsumerRateLimiter = struct {
    entries: [MAX_CONSUMER_BUCKETS]ConsumerBucketEntry,
    count: usize,
    mutex: SpinMutex = .{},

    pub fn init() ConsumerRateLimiter {
        @setEvalBranchQuota(MAX_CONSUMER_BUCKETS * 8);
        var rl = ConsumerRateLimiter{
            .entries = undefined,
            .count = 0,
        };
        for (&rl.entries) |*entry| {
            entry.active = false;
        }
        return rl;
    }

    pub fn checkAndGetInfo(
        self: *ConsumerRateLimiter,
        key: ConsumerKey,
        rps: u32,
        burst: u32,
    ) CheckResult {
        self.mutex.lock();
        defer self.mutex.unlock();

        const entry = self.getOrCreate(key, burst, rps);
        const remaining = entry.bucket.tokens;
        const limit = entry.bucket.max_tokens;

        if (entry.bucket.tryConsume(1)) {
            return .{
                .allowed = true,
                .limit = limit,
                .remaining = if (remaining > 0) remaining - 1 else 0,
                .retry_after_ms = 0,
            };
        }

        const retry_ms = entry.bucket.timeUntilToken();
        return .{
            .allowed = false,
            .limit = limit,
            .remaining = 0,
            .retry_after_ms = retry_ms,
        };
    }

    fn getOrCreate(self: *ConsumerRateLimiter, key: ConsumerKey, burst: u32, rps: u32) *ConsumerBucketEntry {
        const now = clock.realtimeNanos() orelse 0;

        for (&self.entries) |*entry| {
            if (entry.active and entry.key.eql(key)) {
                entry.last_access_ns = now;
                return entry;
            }
        }

        var target: *ConsumerBucketEntry = &self.entries[0];
        var oldest_ns: i128 = std.math.maxInt(i128);

        for (&self.entries) |*entry| {
            if (!entry.active) {
                target = entry;
                break;
            }
            if (entry.last_access_ns < oldest_ns) {
                oldest_ns = entry.last_access_ns;
                target = entry;
            }
        }

        const was_inactive = !target.active;
        target.* = .{
            .key = key,
            .bucket = TokenBucket.init(burst, rps),
            .last_access_ns = now,
            .active = true,
        };
        if (was_inactive) self.count += 1;

        return target;
    }
};

pub const CheckResult = struct {
    allowed: bool,
    limit: u32,
    remaining: u32,
    retry_after_ms: u64,
};

var consumer_limiter: ConsumerRateLimiter = ConsumerRateLimiter.init();

pub fn initConsumerLimiter() void {
    consumer_limiter = ConsumerRateLimiter.init();
}

const rate_limit_header_strings = blk: {
    @setEvalBranchQuota(200_000);
    var strs: [1001][]const u8 = undefined;
    for (0..1001) |i| {
        strs[i] = std.fmt.comptimePrint("{d}", .{i});
    }
    break :blk strs;
};

fn numStr(n: u32) []const u8 {
    if (n < rate_limit_header_strings.len) return rate_limit_header_strings[n];
    return "1000";
}

fn retryStr(ms: u64) []const u8 {
    const s = (ms + 999) / 1000;
    if (s < retry_after_strings.len) return retry_after_strings[s];
    return "60";
}

pub const RateLimitResponse = struct {
    resp: response.Response,
    pause_ms: u64,
};

// Stable storage for per-route 429 headers — avoids dangling pointer
// from returning &[_]Header{runtime_vals} on the stack.
var route_rl_headers: [5]response.Header = .{
    .{ .name = "Retry-After", .value = "0" },
    .{ .name = "X-RateLimit-Limit", .value = "0" },
    .{ .name = "X-RateLimit-Remaining", .value = "0" },
    .{ .name = "Content-Type", .value = "application/json" },
    .{ .name = "Content-Length", .value = "29" },
};

pub fn evaluateRoute(
    consumer_name: []const u8,
    client_ip: ?IpKey,
    cfg: RouteRateLimit,
) ?RateLimitResponse {
    const key: ConsumerKey = switch (cfg.key) {
        .consumer => if (consumer_name.len > 0)
            ConsumerKey.fromName(consumer_name)
        else if (client_ip) |ip|
            ConsumerKey.fromIp(ip)
        else
            return null,
        .ip => if (client_ip) |ip|
            ConsumerKey.fromIp(ip)
        else
            return null,
    };

    const result = consumer_limiter.checkAndGetInfo(key, cfg.requests_per_second, cfg.burst_size);
    if (result.allowed) return null;

    route_rl_headers[0].value = retryStr(result.retry_after_ms);
    route_rl_headers[1].value = numStr(result.limit);
    return .{
        .resp = .{
            .status = 429,
            .headers = &route_rl_headers,
            .body = .{ .bytes = "{\"error\":\"too many requests\"}" },
        },
        .pause_ms = result.retry_after_ms,
    };
}

/// Global rate limiter
var limiter: RateLimiter = RateLimiter.init(.{});

/// Initialize rate limiter with config
pub fn init(config: RateLimiter.Config) void {
    limiter = RateLimiter.init(config);
}

/// Pre-computed Retry-After header values for common retry durations (0-60 seconds).
/// Avoids threadlocal buffer lifetime hazards — all values are comptime string literals.
const retry_after_strings = blk: {
    // 61 × comptimePrint bursts well past the default backward-branch budget.
    @setEvalBranchQuota(20_000);
    var strs: [61][]const u8 = undefined;
    for (0..61) |i| {
        strs[i] = std.fmt.comptimePrint("{d}", .{i});
    }
    break :blk strs;
};

var global_rl_headers: [2]response.Header = .{
    .{ .name = "Retry-After", .value = "0" },
    .{ .name = "Content-Length", .value = "0" },
};

fn tooManyRequests(retry_after: u64) response.Response {
    global_rl_headers[0].value = if (retry_after < retry_after_strings.len)
        retry_after_strings[retry_after]
    else
        "60";

    return .{
        .status = 429,
        .headers = &global_rl_headers,
        .body = .none,
    };
}

/// Create backpressure info for rate limited request
fn backpressure(retry_after_s: u64, resume_after_ms: u64) middleware.BackpressureInfo {
    return .{
        .resp = tooManyRequests(retry_after_s),
        .pause_reads = true,
        .resume_after_ms = resume_after_ms,
    };
}

/// Rate limit middleware function
/// Returns rate_limit_backpressure when bucket is empty to trigger read pausing
pub fn evaluate(ctx: *middleware.Context, req: request.RequestView) middleware.Decision {
    if (!limiter.config.enabled) return .allow;

    // Check excluded paths
    for (limiter.config.exclude_paths) |excluded| {
        if (std.mem.eql(u8, req.path, excluded)) {
            return .allow;
        }
    }

    // Get IP from context
    const ip = if (ctx.client_ip) |ipv4|
        IpKey.fromIpv4(ipv4)
    else if (ctx.client_ip6) |ipv6|
        IpKey.fromIpv6(ipv6)
    else
        // No IP available, allow
        return .allow;

    const info = limiter.checkAndGetInfo(ip) orelse return .allow;
    return .{ .rate_limit_backpressure = backpressure(info.retry_after_s, info.resume_ms) };
}

/// Evaluate without backpressure (for simple rejection scenarios)
pub fn evaluateSimple(ctx: *middleware.Context, req: request.RequestView) middleware.Decision {
    if (!limiter.config.enabled) return .allow;

    // Check excluded paths
    for (limiter.config.exclude_paths) |excluded| {
        if (std.mem.eql(u8, req.path, excluded)) {
            return .allow;
        }
    }

    // Get IP from context
    const ip = if (ctx.client_ip) |ipv4|
        IpKey.fromIpv4(ipv4)
    else if (ctx.client_ip6) |ipv6|
        IpKey.fromIpv6(ipv6)
    else
        return .allow;

    if (limiter.check(ip)) {
        return .allow;
    }

    const retry_after = limiter.getRetryAfter(ip);
    return .{ .reject = tooManyRequests(retry_after) };
}

// Tests
test "token bucket allows requests within limit" {
    var bucket = TokenBucket.init(10, 5);

    // Should allow 10 requests immediately
    var allowed: u32 = 0;
    for (0..15) |_| {
        if (bucket.tryConsume(1)) allowed += 1;
    }

    try std.testing.expectEqual(@as(u32, 10), allowed);
}

test "rate limiter tracks per IP" {
    var rl = RateLimiter.init(.{
        .requests_per_second = 10,
        .burst_size = 5,
        .enabled = true,
        .exclude_paths = &.{},
        .premium_weight = 1,
    });

    const ip1 = IpKey.fromIpv4(.{ 192, 168, 1, 1 });
    const ip2 = IpKey.fromIpv4(.{ 192, 168, 1, 2 });

    // Each IP gets its own bucket
    for (0..5) |_| {
        try std.testing.expect(rl.check(ip1));
        try std.testing.expect(rl.check(ip2));
    }

    // Both should be exhausted now
    try std.testing.expect(!rl.check(ip1));
    try std.testing.expect(!rl.check(ip2));
}

test "excluded paths bypass rate limit" {
    limiter = RateLimiter.init(.{
        .requests_per_second = 1,
        .burst_size = 1,
        .enabled = true,
        .exclude_paths = &.{"/.healthz"},
        .premium_weight = 1,
    });

    var ctx = middleware.Context{
        .client_ip = .{ 10, 0, 0, 1 },
    };

    const health_req = request.RequestView{
        .method = .GET,
        .path = "/.healthz",
        .headers = &.{},
        .body = .{ .slice = "" },
    };

    // Health check always allowed
    for (0..10) |_| {
        try std.testing.expect(evaluate(&ctx, health_req) == .allow);
    }
}
