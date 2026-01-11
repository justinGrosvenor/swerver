const request = @import("../protocol/request.zig");
const response = @import("../response/response.zig");
const x402 = @import("../middleware/x402.zig");

pub const Router = struct {
    policy: x402.Policy,

    pub fn init(policy: x402.Policy) Router {
        return .{
            .policy = policy,
        };
    }

    pub fn handle(self: *Router, req: request.RequestView) response.Response {
        switch (x402.evaluate(req, self.policy)) {
            .allow => {},
            .reject => |resp| return resp,
        }
        return response.Response.ok();
    }
};
