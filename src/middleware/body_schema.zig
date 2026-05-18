const std = @import("std");

pub const SchemaType = enum {
    object,
    array,
    string,
    number,
    integer,
    boolean,
};

pub const Schema = struct {
    schema_type: ?SchemaType = null,
    required: []const []const u8 = &.{},
    properties: []const PropertySchema = &.{},
    min_length: ?u32 = null,
    max_length: ?u32 = null,
    minimum: ?f64 = null,
    maximum: ?f64 = null,
    min_items: ?u32 = null,
    max_items: ?u32 = null,
    items: ?*const Schema = null,
    enum_values: []const []const u8 = &.{},
};

pub const PropertySchema = struct {
    name: []const u8,
    schema: Schema,
};

pub const ValidationError = struct {
    path: [MAX_PATH_DEPTH]PathSegment = undefined,
    path_len: u8 = 0,
    message: []const u8,

    const MAX_PATH_DEPTH = 8;

    const PathSegment = union(enum) {
        field: []const u8,
        index: usize,
    };

    pub fn format(self: *const ValidationError, buf: []u8) []const u8 {
        var pos: usize = 0;
        if (self.path_len == 0) {
            const prefix = "body: ";
            if (pos + prefix.len <= buf.len) {
                @memcpy(buf[pos..][0..prefix.len], prefix);
                pos += prefix.len;
            }
        } else {
            for (self.path[0..self.path_len]) |seg| {
                switch (seg) {
                    .field => |name| {
                        if (pos > 0 and pos + 1 <= buf.len) {
                            buf[pos] = '.';
                            pos += 1;
                        }
                        const n = @min(name.len, buf.len - pos);
                        @memcpy(buf[pos..][0..n], name[0..n]);
                        pos += n;
                    },
                    .index => |idx| {
                        const s = std.fmt.bufPrint(buf[pos..], "[{d}]", .{idx}) catch break;
                        pos += s.len;
                    },
                }
            }
            if (pos + 2 <= buf.len) {
                @memcpy(buf[pos..][0..2], ": ");
                pos += 2;
            }
        }
        const n = @min(self.message.len, buf.len - pos);
        @memcpy(buf[pos..][0..n], self.message[0..n]);
        pos += n;
        return buf[0..pos];
    }
};

const MAX_ERRORS = 8;

pub const ValidationResult = struct {
    errors: [MAX_ERRORS]ValidationError = undefined,
    error_count: u8 = 0,
    valid: bool = true,

    fn addError(self: *ValidationResult, path: []const ValidationError.PathSegment, message: []const u8) void {
        if (self.error_count >= MAX_ERRORS) return;
        self.valid = false;
        var err = &self.errors[self.error_count];
        err.message = message;
        err.path_len = @intCast(@min(path.len, ValidationError.MAX_PATH_DEPTH));
        for (path[0..err.path_len], 0..) |seg, i| {
            err.path[i] = seg;
        }
        self.error_count += 1;
    }
};

pub fn validate(schema: *const Schema, body: []const u8) ValidationResult {
    var result = ValidationResult{};

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const value = std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), body, .{}) catch {
        result.addError(&.{}, "invalid JSON");
        return result;
    };

    var path_buf: [ValidationError.MAX_PATH_DEPTH]ValidationError.PathSegment = undefined;
    validateValue(schema, value, &path_buf, 0, &result);
    return result;
}

fn validateValue(
    schema: *const Schema,
    value: std.json.Value,
    path_buf: *[ValidationError.MAX_PATH_DEPTH]ValidationError.PathSegment,
    depth: u8,
    result: *ValidationResult,
) void {
    if (result.error_count >= MAX_ERRORS) return;

    if (schema.schema_type) |expected_type| {
        if (!typeMatches(expected_type, value)) {
            result.addError(path_buf[0..depth], switch (expected_type) {
                .object => "expected object",
                .array => "expected array",
                .string => "expected string",
                .number => "expected number",
                .integer => "expected integer",
                .boolean => "expected boolean",
            });
            return;
        }
    }

    if (schema.enum_values.len > 0) {
        switch (value) {
            .string => |s| {
                var found = false;
                for (schema.enum_values) |ev| {
                    if (std.mem.eql(u8, s, ev)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    result.addError(path_buf[0..depth], "value not in enum");
                }
            },
            else => {
                result.addError(path_buf[0..depth], "enum requires string value");
            },
        }
    }

    switch (value) {
        .string => |s| {
            if (schema.min_length) |min| {
                if (s.len < min) {
                    result.addError(path_buf[0..depth], "string too short");
                }
            }
            if (schema.max_length) |max| {
                if (s.len > max) {
                    result.addError(path_buf[0..depth], "string too long");
                }
            }
        },
        .integer => |i| {
            const f: f64 = @floatFromInt(i);
            validateNumeric(schema, f, path_buf, depth, result);
        },
        .float => |f| {
            validateNumeric(schema, f, path_buf, depth, result);
        },
        .object => |obj| {
            for (schema.required) |req_field| {
                if (!obj.contains(req_field)) {
                    if (depth < ValidationError.MAX_PATH_DEPTH) {
                        path_buf[depth] = .{ .field = req_field };
                        result.addError(path_buf[0 .. depth + 1], "required field missing");
                    }
                }
            }
            if (schema.properties.len > 0 and depth < ValidationError.MAX_PATH_DEPTH - 1) {
                for (schema.properties) |prop| {
                    if (obj.get(prop.name)) |prop_value| {
                        path_buf[depth] = .{ .field = prop.name };
                        validateValue(&prop.schema, prop_value, path_buf, depth + 1, result);
                    }
                }
            }
        },
        .array => |arr| {
            if (schema.min_items) |min| {
                if (arr.items.len < min) {
                    result.addError(path_buf[0..depth], "array too short");
                }
            }
            if (schema.max_items) |max| {
                if (arr.items.len > max) {
                    result.addError(path_buf[0..depth], "array too long");
                }
            }
            if (schema.items) |item_schema| {
                if (depth < ValidationError.MAX_PATH_DEPTH - 1) {
                    for (arr.items, 0..) |item, idx| {
                        if (result.error_count >= MAX_ERRORS) break;
                        path_buf[depth] = .{ .index = idx };
                        validateValue(item_schema, item, path_buf, depth + 1, result);
                    }
                }
            }
        },
        else => {},
    }
}

fn validateNumeric(
    schema: *const Schema,
    f: f64,
    path_buf: *[ValidationError.MAX_PATH_DEPTH]ValidationError.PathSegment,
    depth: u8,
    result: *ValidationResult,
) void {
    if (schema.minimum) |min| {
        if (f < min) {
            result.addError(path_buf[0..depth], "number below minimum");
        }
    }
    if (schema.maximum) |max| {
        if (f > max) {
            result.addError(path_buf[0..depth], "number above maximum");
        }
    }
}

fn typeMatches(expected: SchemaType, value: std.json.Value) bool {
    return switch (expected) {
        .object => value == .object,
        .array => value == .array,
        .string => value == .string,
        .number => value == .integer or value == .float,
        .integer => value == .integer,
        .boolean => value == .bool,
    };
}

pub fn parseSchema(allocator: std.mem.Allocator, value: std.json.Value) !Schema {
    if (value != .object) return error.InvalidSchema;
    const obj = value.object;

    var schema = Schema{};

    if (obj.get("type")) |t| {
        if (t != .string) return error.InvalidSchema;
        schema.schema_type = std.meta.stringToEnum(SchemaType, t.string) orelse return error.InvalidSchema;
    }

    if (obj.get("required")) |req| {
        if (req != .array) return error.InvalidSchema;
        const required = try allocator.alloc([]const u8, req.array.items.len);
        for (req.array.items, 0..) |item, i| {
            if (item != .string) return error.InvalidSchema;
            required[i] = item.string;
        }
        schema.required = required;
    }

    if (obj.get("properties")) |props| {
        if (props != .object) return error.InvalidSchema;
        const properties = try allocator.alloc(PropertySchema, props.object.count());
        var pi: usize = 0;
        var it = props.object.iterator();
        while (it.next()) |entry| {
            properties[pi] = .{
                .name = entry.key_ptr.*,
                .schema = try parseSchema(allocator, entry.value_ptr.*),
            };
            pi += 1;
        }
        schema.properties = properties;
    }

    if (obj.get("minLength")) |v| schema.min_length = jsonU32(v);
    if (obj.get("maxLength")) |v| schema.max_length = jsonU32(v);
    if (obj.get("minimum")) |v| schema.minimum = jsonF64(v);
    if (obj.get("maximum")) |v| schema.maximum = jsonF64(v);
    if (obj.get("minItems")) |v| schema.min_items = jsonU32(v);
    if (obj.get("maxItems")) |v| schema.max_items = jsonU32(v);

    if (obj.get("items")) |items_val| {
        const item_schema = try allocator.create(Schema);
        item_schema.* = try parseSchema(allocator, items_val);
        schema.items = item_schema;
    }

    if (obj.get("enum")) |e| {
        if (e != .array) return error.InvalidSchema;
        const enums = try allocator.alloc([]const u8, e.array.items.len);
        for (e.array.items, 0..) |item, i| {
            if (item != .string) return error.InvalidSchema;
            enums[i] = item.string;
        }
        schema.enum_values = enums;
    }

    return schema;
}

fn jsonU32(v: std.json.Value) ?u32 {
    return switch (v) {
        .integer => |i| if (i >= 0 and i <= std.math.maxInt(u32)) @intCast(i) else null,
        .float => |f| if (f >= 0 and f <= @as(f64, @floatFromInt(std.math.maxInt(u32)))) @intFromFloat(f) else null,
        else => null,
    };
}

fn jsonF64(v: std.json.Value) ?f64 {
    return switch (v) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        else => null,
    };
}

pub fn formatErrorResponse(result: *const ValidationResult, buf: []u8) []const u8 {
    var pos: usize = 0;

    const prefix = "{\"error\":\"validation_failed\",\"details\":[";
    if (pos + prefix.len > buf.len) return buf[0..0];
    @memcpy(buf[pos..][0..prefix.len], prefix);
    pos += prefix.len;

    var detail_buf: [256]u8 = undefined;
    for (result.errors[0..result.error_count], 0..) |*err, i| {
        if (i > 0) {
            if (pos + 1 > buf.len) break;
            buf[pos] = ',';
            pos += 1;
        }
        if (pos + 1 > buf.len) break;
        buf[pos] = '"';
        pos += 1;

        const detail = err.format(&detail_buf);
        for (detail) |ch| {
            if (pos + 2 > buf.len) break;
            if (ch == '"') {
                buf[pos] = '\\';
                pos += 1;
            }
            buf[pos] = ch;
            pos += 1;
        }

        if (pos + 1 > buf.len) break;
        buf[pos] = '"';
        pos += 1;
    }

    const suffix = "]}";
    if (pos + suffix.len <= buf.len) {
        @memcpy(buf[pos..][0..suffix.len], suffix);
        pos += suffix.len;
    }
    return buf[0..pos];
}

// ── Tests ──

test "validate type: object" {
    const schema = Schema{ .schema_type = .object };
    const r1 = validate(&schema, "{}");
    try std.testing.expect(r1.valid);

    const r2 = validate(&schema, "\"hello\"");
    try std.testing.expect(!r2.valid);
    try std.testing.expectEqualStrings("expected object", r2.errors[0].message);
}

test "validate required fields" {
    const schema = Schema{
        .schema_type = .object,
        .required = &.{ "name", "email" },
    };

    const r1 = validate(&schema, "{\"name\":\"Alice\",\"email\":\"a@b.com\"}");
    try std.testing.expect(r1.valid);

    const r2 = validate(&schema, "{\"name\":\"Alice\"}");
    try std.testing.expect(!r2.valid);
    try std.testing.expectEqual(@as(u8, 1), r2.error_count);
    try std.testing.expectEqualStrings("required field missing", r2.errors[0].message);
}

test "validate string constraints" {
    const props = [_]PropertySchema{
        .{ .name = "name", .schema = .{ .schema_type = .string, .min_length = 2, .max_length = 5 } },
    };
    const schema = Schema{
        .schema_type = .object,
        .properties = &props,
    };

    const r1 = validate(&schema, "{\"name\":\"abc\"}");
    try std.testing.expect(r1.valid);

    const r2 = validate(&schema, "{\"name\":\"a\"}");
    try std.testing.expect(!r2.valid);
    try std.testing.expectEqualStrings("string too short", r2.errors[0].message);

    const r3 = validate(&schema, "{\"name\":\"toolong\"}");
    try std.testing.expect(!r3.valid);
}

test "validate number constraints" {
    const props = [_]PropertySchema{
        .{ .name = "age", .schema = .{ .schema_type = .number, .minimum = 0, .maximum = 150 } },
    };
    const schema = Schema{
        .schema_type = .object,
        .properties = &props,
    };

    const r1 = validate(&schema, "{\"age\":25}");
    try std.testing.expect(r1.valid);

    const r2 = validate(&schema, "{\"age\":-1}");
    try std.testing.expect(!r2.valid);
    try std.testing.expectEqualStrings("number below minimum", r2.errors[0].message);
}

test "validate array constraints" {
    const item_schema = Schema{ .schema_type = .string };
    const schema = Schema{
        .schema_type = .array,
        .min_items = 1,
        .max_items = 3,
        .items = &item_schema,
    };

    const r1 = validate(&schema, "[\"a\",\"b\"]");
    try std.testing.expect(r1.valid);

    const r2 = validate(&schema, "[]");
    try std.testing.expect(!r2.valid);
    try std.testing.expectEqualStrings("array too short", r2.errors[0].message);

    const r3 = validate(&schema, "[1,2]");
    try std.testing.expect(!r3.valid);
    try std.testing.expectEqualStrings("expected string", r3.errors[0].message);
}

test "validate enum" {
    const schema = Schema{
        .schema_type = .string,
        .enum_values = &.{ "active", "inactive", "pending" },
    };

    const r1 = validate(&schema, "\"active\"");
    try std.testing.expect(r1.valid);

    const r2 = validate(&schema, "\"deleted\"");
    try std.testing.expect(!r2.valid);
    try std.testing.expectEqualStrings("value not in enum", r2.errors[0].message);
}

test "validate invalid JSON" {
    const schema = Schema{ .schema_type = .object };
    const r = validate(&schema, "{broken");
    try std.testing.expect(!r.valid);
    try std.testing.expectEqualStrings("invalid JSON", r.errors[0].message);
}

test "parseSchema from JSON value" {
    const json =
        \\{"type":"object","required":["name"],"properties":{"name":{"type":"string","minLength":1},"age":{"type":"integer","minimum":0,"maximum":150}}}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const value = try std.json.parseFromSliceLeaky(std.json.Value, alloc, json, .{});
    const schema = try parseSchema(alloc, value);

    try std.testing.expect(schema.schema_type == .object);
    try std.testing.expectEqual(@as(usize, 1), schema.required.len);
    try std.testing.expectEqualStrings("name", schema.required[0]);
    try std.testing.expectEqual(@as(usize, 2), schema.properties.len);
}

test "formatErrorResponse" {
    const schema = Schema{
        .schema_type = .object,
        .required = &.{"name"},
    };
    const r = validate(&schema, "{}");
    try std.testing.expect(!r.valid);

    var buf: [512]u8 = undefined;
    const json_out = formatErrorResponse(&r, &buf);
    try std.testing.expect(std.mem.indexOf(u8, json_out, "validation_failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_out, "required field missing") != null);
}

test "nested object validation" {
    const addr_props = [_]PropertySchema{
        .{ .name = "city", .schema = .{ .schema_type = .string, .min_length = 1 } },
    };
    const props = [_]PropertySchema{
        .{ .name = "address", .schema = .{
            .schema_type = .object,
            .required = &.{"city"},
            .properties = &addr_props,
        } },
    };
    const schema = Schema{
        .schema_type = .object,
        .properties = &props,
    };

    const r1 = validate(&schema, "{\"address\":{\"city\":\"NYC\"}}");
    try std.testing.expect(r1.valid);

    const r2 = validate(&schema, "{\"address\":{}}");
    try std.testing.expect(!r2.valid);

    const r3 = validate(&schema, "{\"address\":{\"city\":\"\"}}");
    try std.testing.expect(!r3.valid);
    try std.testing.expectEqualStrings("string too short", r3.errors[0].message);
}
