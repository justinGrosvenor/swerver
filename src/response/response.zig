pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Response = struct {
    status: u16,
    headers: []const Header,
    body: []const u8,

    pub fn ok() Response {
        return .{
            .status = 200,
            .headers = &[_]Header{},
            .body = "",
        };
    }
};
