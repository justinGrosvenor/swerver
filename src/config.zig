const std = @import("std");

/// One TCP listener with its own protocol config. A single process can bind
/// many of these (multi-listener model): e.g. plaintext h1, h2c-only, TLS
/// h1/h2, and QUIC/h3 on distinct ports, all served by the normal worker set.
pub const ListenerConfig = struct {
    address: []const u8 = "0.0.0.0",
    port: u16,
    use_tls: bool = false,
    h2c_only: bool = false,
    quic_enabled: bool = false,
    quic_port: u16 = 0,
};

pub const ServerConfig = struct {
    address: []const u8,
    port: u16,
    max_connections: usize,
    timeouts: Timeouts,
    limits: Limits,
    backpressure: Backpressure,
    buffer_pool: BufferPoolConfig,
    x402: X402Config,
    http2: Http2Config,
    tls: TlsConfig,
    quic: QuicConfig,
    admin: AdminConfig,
    otel: OtelConfig,
    /// Native PostgreSQL client. Disabled by default.
    postgres: PostgresConfig = .{},
    /// Root directory for static file serving. Empty means disabled.
    static_root: []const u8,
    /// Allowed Host header values. Empty slice means all hosts are accepted.
    /// When non-empty, requests with a Host header not in this list are rejected with 400.
    allowed_hosts: []const []const u8 = &.{},
    /// Number of worker processes. 1 = single-process (no fork). 0 = auto-detect
    /// CPU count (the default). NOTE: with a wasm control socket configured, only
    /// one worker becomes the Nether primary client; set `workers: 1` if parking
    /// filters / tenant cold starts must work on every worker (see master.zig).
    workers: u16 = 0,
    /// Max connections per IP address. 0 = unlimited.
    per_ip_limit: u16 = 0,
    /// Graceful shutdown drain timeout in milliseconds.
    drain_timeout_ms: u32 = 30_000,
    /// Disable security headers, metrics, and access logging middleware.
    /// Use for pure benchmark mode where middleware overhead matters.
    disable_middleware: bool = false,
    /// Disable the preencoded HTTP/1.1 response cache. When enabled it
    /// serves common error responses (and any opt-in hot endpoints) as
    /// precomputed bytes, bypassing the router, middleware, and encoder.
    /// Off by default so a default server takes the normal pipeline; set
    /// `preencoded: true` in the config to opt in.
    disable_preencoded: bool = true,
    /// Cache static files (and their precompressed siblings) in memory on
    /// first serve, keyed by path + negotiated encoding. Removes the
    /// per-request open/fstat/read syscalls. Per-worker, lazy-populated,
    /// bounded; Date stays fresh (re-encoded per response, never cached).
    cache_static_files: bool = false,
    /// Explicit per-port listener configs. Empty means single-listener mode
    /// (the legacy address/port/tls/quic fields are used via listenerForPort).
    listeners: []const ListenerConfig = &.{},

    /// Resolve the listener config for a given local port. Falls back to a
    /// config synthesized from the legacy single-port fields when `listeners`
    /// is empty or the port isn't found (keeps single-listener configs working).
    pub fn listenerForPort(self: *const ServerConfig, port: u16) ListenerConfig {
        for (self.listeners) |l| if (l.port == port) return l;
        return .{
            .address = self.address,
            .port = self.port,
            // Mirror the tcp_tls_provider build condition in server.zig:
            // TLS is "on" for the legacy listener iff a cert path is set.
            .use_tls = (self.tls.cert_path.len > 0),
            .h2c_only = self.http2.h2c_only,
            .quic_enabled = self.quic.enabled,
            .quic_port = self.quic.port,
        };
    }

    pub fn default() ServerConfig {
        return .{
            .address = "0.0.0.0",
            .port = 8080,
            .max_connections = 2048,
            .timeouts = .{},
            .limits = .{},
            .backpressure = .{},
            .buffer_pool = .{},
            .x402 = .{},
            .http2 = .{},
            .tls = .{},
            .quic = .{},
            .admin = .{},
            .otel = .{},
            .static_root = "",
            .allowed_hosts = &.{},
            .workers = 0,
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
        if (self.timeouts.write_ms > self.timeouts.idle_ms) return error.InvalidTimeouts;
        if (self.limits.max_header_count == 0) return error.InvalidHeaderTable;
        if (self.http2.max_frame_size < 16384 or self.http2.max_frame_size > 16777215) return error.InvalidHttp2Config;
        // TLS: both cert and key must be provided or both empty
        if ((self.tls.cert_path.len == 0) != (self.tls.key_path.len == 0)) return error.InvalidTlsConfig;
        if (self.x402.enabled and self.x402.payment_required_b64.len == 0) return error.InvalidX402Config;
        if (self.quic.enabled) {
            if (self.quic.cert_path.len == 0 or self.quic.key_path.len == 0) return error.InvalidQuicConfig;
            if (self.quic.max_idle_timeout_ms == 0) return error.InvalidQuicConfig;
            if (self.quic.max_streams_bidi == 0 and self.quic.max_streams_uni == 0) return error.InvalidQuicConfig;
        }
        if (self.admin.enabled and self.admin.api_key.len == 0) return error.InvalidAdminConfig;
        if (self.postgres.enabled) {
            if (self.postgres.host.len == 0 or self.postgres.user.len == 0) return error.InvalidPostgresConfig;
            if (self.postgres.pool_size_per_worker == 0 or self.postgres.pool_size_per_worker > 4) return error.InvalidPostgresConfig;
        }
        if (self.workers > 256) return error.InvalidWorkerCount;
        if (self.static_root.len > 0) {
            // Reject paths containing null bytes
            for (self.static_root) |ch| {
                if (ch == 0) return error.InvalidStaticRoot;
            }
            // Reject paths with parent directory traversal
            if (std.mem.indexOf(u8, self.static_root, "..") != null) return error.InvalidStaticRoot;
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
    max_body_bytes: usize = 32 * 1024 * 1024,
    max_header_count: usize = 128,
};

pub const Backpressure = struct {
    read_high_water: usize = 256 * 1024,
    write_high_water: usize = 256 * 1024,
    read_low_water: usize = 128 * 1024,
    write_low_water: usize = 128 * 1024,
};

pub const BufferPoolConfig = struct {
    buffer_size: usize = 64 * 1024,
    buffer_count: usize = 4096,
    /// Separate pool for large request body accumulation (uploads).
    /// Prevents large uploads from exhausting the hot-path pool.
    /// Default: 32 × 1MB = 32MB per worker, enough for a few
    /// concurrent 20MB uploads.
    body_buffer_size: usize = 1024 * 1024,
    body_buffer_count: usize = 32,
};

pub const X402Config = struct {
    enabled: bool = false,
    payment_required_b64: []const u8 = "",
    payment_required_json: []const u8 = "",
    facilitator_url: []const u8 = "",
    facilitator_timeout_ms: u32 = 5_000,
};

pub const Http2Config = struct {
    /// Maximum number of concurrent streams per connection
    max_streams: usize = 128,
    /// Maximum header list size in bytes
    max_header_list_size: usize = 8192,
    /// Initial flow control window size (RFC 9113 §6.5.2 default is 65535,
    /// but larger windows improve throughput for multiplexed body-bearing
    /// requests by reducing WINDOW_UPDATE round-trips under load)
    initial_window_size: u32 = 1048576,
    /// Maximum frame size (must be 16384..16777215 per RFC 9113 §4.2)
    max_frame_size: u32 = 16384,
    /// Maximum HPACK dynamic table size in bytes
    max_dynamic_table_size: usize = 4096,
    /// h2c-only listener: when true, a plaintext connection MUST begin with
    /// the HTTP/2 connection preface (prior-knowledge h2c). Connections that
    /// start with anything else (e.g. an HTTP/1.1 request) are refused rather
    /// than served as HTTP/1.1, so a dedicated h2c port can't silently fall
    /// back to h1. Default false (opportunistic h1→h2 upgrade via sniff).
    h2c_only: bool = false,
};

pub const TlsCertificate = struct {
    hostnames: []const [:0]const u8,
    cert_path: [:0]const u8,
    key_path: [:0]const u8,
};

pub const TlsConfig = struct {
    /// Path to PEM certificate file (empty = TLS disabled on TCP)
    cert_path: [:0]const u8 = "",
    /// Path to PEM private key file
    key_path: [:0]const u8 = "",
    /// Additional certificates for SNI-based routing (optional)
    certificates: []const TlsCertificate = &.{},
    /// mTLS: path to CA certificate for client verification (empty = no mTLS)
    client_ca_path: [:0]const u8 = "",
    /// mTLS: require client certificate (vs optional verification)
    client_cert_required: bool = true,
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

/// PostgreSQL client TLS policy. The subset of
/// libpq's sslmode values that have honest semantics: `prefer`/`allow`
/// (opportunistic) and `verify-ca` (chain without hostname) are
/// deliberately not offered.
pub const PgSslMode = enum {
    /// Plaintext; the SSLRequest is never sent.
    disable,
    /// Encrypt, but skip certificate verification entirely. Discouraged:
    /// an active MITM can present any certificate. Exists for libpq
    /// parity and broken-PKI escape hatches only — use verify_full.
    require,
    /// Chain verification against the trust store plus hostname/IP
    /// verification (RFC 6125). The fail-safe default.
    verify_full,
};

/// Native PostgreSQL client. Populated from the config
/// file's "postgres" block; host/port/user/database/sslmode come from
/// parsing the `url` field. The password is read from the environment
/// variable named by `password_env` at server init — never from the
/// config file.
pub const PostgresConfig = struct {
    enabled: bool = false,
    host: []const u8 = "",
    port: u16 = 5432,
    user: []const u8 = "",
    database: []const u8 = "",
    /// Name of the environment variable holding the password.
    password_env: []const u8 = "",
    /// Connections per worker process (1..4).
    pool_size_per_worker: u8 = 2,
    /// Enforced by the query API as a per-query deadline.
    statement_timeout_ms: u32 = 5_000,
    /// Explicit opt-in for answering a cleartext-password request over a
    /// PLAINTEXT connection. Cleartext over an established TLS channel
    /// is always acceptable (the channel is encrypted and, under
    /// verify_full, the server is authenticated).
    allow_cleartext_password: bool = false,
    /// TLS policy; verify_full unless the URL's sslmode says otherwise.
    sslmode: PgSslMode = .verify_full,
    /// Optional CA bundle (PEM path) replacing the system trust store
    /// for verify_full — e.g. a managed database's private root.
    ssl_root_cert: [:0]const u8 = "",
};

pub const AdminConfig = struct {
    enabled: bool = false,
    port: u16 = 9180,
    address: []const u8 = "127.0.0.1",
    api_key: []const u8 = "",
};

pub const OtelConfig = struct {
    enabled: bool = false,
    collector_url: []const u8 = "http://localhost:4318",
    service_name: []const u8 = "swerver",
    flush_interval_s: u32 = 5,
    sample_rate: u16 = 100,
    max_batch_size: u16 = 256,
    /// Extra request headers for the OTLP exporter, in the
    /// OTEL_EXPORTER_OTLP_HEADERS convention: `key1=value1,key2=value2`.
    /// Each becomes a `Key: value` header on the POST — used for backend auth
    /// (e.g. `Authorization=Bearer …`, `x-honeycomb-team=…`). Pair with an
    /// `https://` collector_url so secrets aren't sent in the clear.
    headers: []const u8 = "",
};

test "listenerForPort returns matching explicit listener" {
    const listeners = [_]ListenerConfig{
        .{ .port = 18080, .h2c_only = false },
        .{ .port = 18082, .h2c_only = true, .use_tls = false },
    };
    var cfg = ServerConfig.default();
    cfg.listeners = &listeners;

    const l0 = cfg.listenerForPort(18080);
    try std.testing.expectEqual(@as(u16, 18080), l0.port);
    try std.testing.expectEqual(false, l0.h2c_only);

    const l1 = cfg.listenerForPort(18082);
    try std.testing.expectEqual(@as(u16, 18082), l1.port);
    try std.testing.expectEqual(true, l1.h2c_only);
}

test "listenerForPort falls back to legacy single-port fields" {
    var cfg = ServerConfig.default();
    cfg.address = "127.0.0.1";
    cfg.port = 9000;
    cfg.http2.h2c_only = true;
    // No explicit listeners → synthesized fallback for any port lookup.
    const l = cfg.listenerForPort(12345);
    try std.testing.expectEqual(@as(u16, 9000), l.port);
    try std.testing.expectEqualStrings("127.0.0.1", l.address);
    try std.testing.expectEqual(true, l.h2c_only);
    // No cert configured → fallback use_tls is false.
    try std.testing.expectEqual(false, l.use_tls);
}

test "listenerForPort fallback reflects TLS cert presence" {
    var cfg = ServerConfig.default();
    cfg.tls.cert_path = "/tmp/cert.pem";
    const l = cfg.listenerForPort(cfg.port);
    try std.testing.expectEqual(true, l.use_tls);
}

pub const ConfigError = error{
    InvalidMaxConnections,
    InvalidBufferPool,
    InvalidBackpressure,
    InvalidTimeouts,
    InvalidHeaderTable,
    InvalidHttp2Config,
    InvalidTlsConfig,
    InvalidX402Config,
    InvalidQuicConfig,
    InvalidAdminConfig,
    InvalidPostgresConfig,
    InvalidStaticRoot,
    InvalidWorkerCount,
};
