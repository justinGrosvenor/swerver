const std = @import("std");
const request = @import("../protocol/request.zig");
const response = @import("../response/response.zig");
const middleware = @import("middleware.zig");
const clock = @import("../runtime/clock.zig");

/// Rate Limiting Middleware
///
/// Implements token bucket rate limiting per IP address.
/// Zero heap allocations using fixed-size bucket storage.

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
    /// Mutex for thread-safe access
    mutex: std.Thread.Mutex = .{},

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

    /// Get retry-after header value in seconds
    pub fn getRetryAfter(self: *RateLimiter, ip: IpKey) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (&self.entries) |*entry| {
            if (entry.active and entry.key.eql(ip)) {
                return (entry.bucket.timeUntilToken() + 999) / 1000; // Round up to seconds
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
        return 1000; // Default 1 second
    }
};

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

/// 429 response with Retry-After header
fn tooManyRequests(retry_after: u64) response.Response {
    // Use pre-computed string table for common values (0-60s)
    const retry_str = if (retry_after < retry_after_strings.len)
        retry_after_strings[retry_after]
    else
        "60";

    return .{
        .status = 429,
        .headers = &[_]response.Header{
            .{ .name = "Retry-After", .value = retry_str },
            .{ .name = "Content-Length", .value = "0" },
        },
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

    // Check rate limit
    if (limiter.check(ip)) {
        return .allow;
    }

    // Rate limited - return backpressure decision to pause reads
    const retry_after_s = limiter.getRetryAfter(ip);
    const resume_ms = limiter.getTimeUntilToken(ip);
    return .{ .rate_limit_backpressure = backpressure(retry_after_s, resume_ms) };
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
        .body = "",
    };

    // Health check always allowed
    for (0..10) |_| {
        try std.testing.expect(evaluate(&ctx, health_req) == .allow);
    }
}
