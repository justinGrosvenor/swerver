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

pub const ConfigError = error{
    InvalidMaxConnections,
    InvalidBufferPool,
    InvalidBackpressure,
    InvalidTimeouts,
    InvalidHeaderTable,
    InvalidPinnedBuffers,
    InvalidX402Config,
};
