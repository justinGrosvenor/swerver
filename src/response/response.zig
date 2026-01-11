const request = @import("../protocol/request.zig");

pub const Header = request.Header;

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
