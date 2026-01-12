const std = @import("std");

pub const ServerConfig = struct {
    address: []const u8,
    port: u16,
    max_connections: usize,
    timeouts: Timeouts,
    limits: Limits,
    backpressure: Backpressure,
    buffer_pool: BufferPoolConfig,
    pinned_buffers_per_conn: u8,
    x402: X402Config,
    quic: QuicConfig,
    /// Root directory for static file serving. Empty means disabled.
    static_root: []const u8,

    pub fn default() ServerConfig {
        return .{
            .address = "0.0.0.0",
            .port = 8080,
            .max_connections = 2048,
            .timeouts = .{},
            .limits = .{},
            .backpressure = .{},
            .buffer_pool = .{},
            .pinned_buffers_per_conn = 2,
            .x402 = .{},
            .quic = .{},
            .static_root = "",
        };
    }

    pub fn validate(self: ServerConfig) ConfigError!void {
        if (self.max_connections == 0) return error.InvalidMaxConnections;
        if (self.buffer_pool.buffer_size == 0 or self.buffer_pool.buffer_count == 0) {
            return error.InvalidBufferPool;
        }
        if (self.buffer_pool.buffer_count < self.max_connections * 2) {
            return error.InvalidBufferPool;
        }
        if (self.backpressure.read_high_water % self.buffer_pool.buffer_size != 0 or
            self.backpressure.write_high_water % self.buffer_pool.buffer_size != 0)
        {
            return error.InvalidBackpressure;
        }
        if (self.backpressure.read_low_water > self.backpressure.read_high_water or
            self.backpressure.write_low_water > self.backpressure.write_high_water)
        {
            return error.InvalidBackpressure;
        }
        if (self.timeouts.idle_ms == 0 or self.timeouts.header_ms == 0 or
            self.timeouts.body_ms == 0 or self.timeouts.write_ms == 0)
        {
            return error.InvalidTimeouts;
        }
        if (self.timeouts.header_ms > self.timeouts.idle_ms) return error.InvalidTimeouts;
        if (self.limits.max_header_count == 0) return error.InvalidHeaderTable;
        if (self.pinned_buffers_per_conn == 0) return error.InvalidPinnedBuffers;
        if (self.x402.enabled and self.x402.payment_required_b64.len == 0) return error.InvalidX402Config;
        if (self.quic.enabled) {
            if (self.quic.cert_path.len == 0 or self.quic.key_path.len == 0) return error.InvalidQuicConfig;
            if (self.quic.max_idle_timeout_ms == 0) return error.InvalidQuicConfig;
            if (self.quic.max_streams_bidi == 0 and self.quic.max_streams_uni == 0) return error.InvalidQuicConfig;
        }
    }
};

pub const Timeouts = struct {
    idle_ms: u32 = 60_000,
    header_ms: u32 = 10_000,
    body_ms: u32 = 30_000,
    write_ms: u32 = 30_000,
};

pub const Limits = struct {
    max_header_bytes: usize = 32 * 1024,
    max_body_bytes: usize = 8 * 1024 * 1024,
    max_header_count: usize = 128,
};

pub const Backpressure = struct {
    read_high_water: usize = 256 * 1024,
    write_high_water: usize = 256 * 1024,
    read_low_water: usize = 128 * 1024,
    write_low_water: usize = 128 * 1024,
};

pub const BufferPoolConfig = struct {
    buffer_size: usize = 16 * 1024,
    buffer_count: usize = 4096,
};

pub const X402Config = struct {
    enabled: bool = false,
    payment_required_b64: []const u8 = "",
};

pub const QuicConfig = struct {
    enabled: bool = false,
    port: u16 = 443,
    cert_path: [:0]const u8 = "",
    key_path: [:0]const u8 = "",
    max_idle_timeout_ms: u32 = 30_000,
    max_streams_bidi: u64 = 100,
    max_streams_uni: u64 = 100,
    initial_max_data: u64 = 10 * 1024 * 1024,
    initial_max_stream_data_bidi_local: u64 = 1024 * 1024,
    initial_max_stream_data_bidi_remote: u64 = 1024 * 1024,
    initial_max_stream_data_uni: u64 = 1024 * 1024,
    ack_delay_exponent: u8 = 3,
    max_ack_delay_ms: u32 = 25,
    active_connection_id_limit: u64 = 2,
    /// Max-age for Alt-Svc header (seconds)
    alt_svc_max_age: u32 = 86400,

    /// Build Alt-Svc header value for advertising HTTP/3
    /// Format: h3=":<port>"; ma=<max_age>
    pub fn buildAltSvcHeader(self: QuicConfig, buf: []u8) ![]const u8 {
        if (!self.enabled) return "";
        return std.fmt.bufPrint(buf, "h3=\":{d}\"; ma={d}", .{ self.port, self.alt_svc_max_age }) catch return error.BufferTooSmall;
    }
};

pub const ConfigError = error{
    InvalidMaxConnections,
    InvalidBufferPool,
    InvalidBackpressure,
    InvalidTimeouts,
    InvalidHeaderTable,
    InvalidPinnedBuffers,
    InvalidX402Config,
    InvalidQuicConfig,
};
