pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const RequestView = struct {
    method: []const u8,
    path: []const u8,
    headers: []const Header,
    body: []const u8,
};
