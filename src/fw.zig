const std = @import("std");
const Allocator = std.mem.Allocator;

pub const LdHeader = struct {
    crc: u32,
    data_length: u32,
    data_offset: u32,
    load_addr: u32,
    exe_addr: u32,
    header_sum: u32,
    code_sum: u32,
    next_header: u32,
    options: u32,

    const Self = @This();

    const OPTION_COMPRESS: u32 = 1;
    const OPTION_02: u32 = 2;
    const OPTION_08: u32 = 8;

    inline fn isOptionSet(self: *const Self, option: u32) bool {
        return self.options & option == option;
    }

    pub fn isCompressed(self: *const Self) bool {
        return self.isOptionSet(OPTION_COMPRESS);
    }

    pub fn fromFile(r: anytype) !Self {
        return Self{
            .crc = try r.readIntLittle(u32),
            .data_length = try r.readIntLittle(u32),
            .data_offset = try r.readIntLittle(u32),
            .load_addr = try r.readIntLittle(u32),
            .exe_addr = try r.readIntLittle(u32),
            .header_sum = try r.readIntLittle(u32),
            .code_sum = try r.readIntLittle(u32),
            .next_header = try r.readIntLittle(u32),
            .options = try r.readIntLittle(u32),
        };
    }

    pub fn isValid(self: *const Self) bool {
        var sum: u32 = self.data_length + self.data_offset + self.load_addr + self.exe_addr;

        if (!(self.isOptionSet(OPTION_02) or self.isOptionSet(OPTION_08)))
            sum += self.code_sum;

        return sum == self.header_sum;
    }
};

pub const LdAppInfo = struct {
    app_type: []u8,
    build_date: []u8,
    version: []u8,
    descriptors: []u8,
    copyright: []u8,
    allocator: Allocator,

    const Self = @This();

    pub fn fromFile(r: anytype, allocator: Allocator) !Self {
        const app_type = try r.readUntilDelimiterAlloc(allocator, 0, 512);
        errdefer allocator.free(app_type);
        const build_date = try r.readUntilDelimiterAlloc(allocator, 0, 512);
        errdefer allocator.free(build_date);
        const version = try r.readUntilDelimiterAlloc(allocator, 0, 512);
        errdefer allocator.free(version);
        const descriptors = try r.readUntilDelimiterAlloc(allocator, 0, 512);
        errdefer allocator.free(descriptors);
        const copyright = try r.readUntilDelimiterAlloc(allocator, 0, 512);
        return Self{
            .app_type = app_type,
            .build_date = build_date,
            .version = version,
            .descriptors = descriptors,
            .copyright = copyright,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.app_type);
        self.app_type = undefined;
        self.allocator.free(self.build_date);
        self.build_date = undefined;
        self.allocator.free(self.version);
        self.version = undefined;
        self.allocator.free(self.descriptors);
        self.descriptors = undefined;
        self.allocator.free(self.copyright);
        self.copyright = undefined;
    }
};

pub const LdFile = struct {
    header: LdHeader,
    app_info: LdAppInfo,
    contents: []u8,
    allocator: Allocator,

    const Self = @This();

    /// Needs an allocator for storing the firmware contents
    pub fn fromFile(file: anytype, allocator: Allocator) !Self {
        const reader = file.reader();
        const header = try LdHeader.fromFile(reader);
        if (!header.isValid())
            return error.InvalidHeader;
        // try to allocate the larger buffer first
        const contents = try allocator.alloc(u8, header.data_length);
        errdefer allocator.free(contents);
        // read the app info
        var app_info = try LdAppInfo.fromFile(reader, allocator);
        errdefer app_info.deinit();

        // read data here
        try file.seekTo(header.data_offset);
        try reader.readNoEof(contents);

        return Self{
            .header = header,
            .app_info = app_info,
            .contents = contents,
            .allocator = allocator,
        };
    }

    pub fn print(self: *const Self, writer: anytype) !void {
        const header = &self.header;
        const info = &self.app_info;
        try writer.print(
            \\          crc: 0x{x}
            \\  data length: {}
            \\  data offset: {}
            \\    load addr: 0x{x}
            \\     exe addr: 0x{x}
            \\   header sum: 0x{x}
            \\     code sum: 0x{x}
            \\  next header: 0x{x}
            \\is compressed: {}
            \\     is valid: {}
            \\
        , .{
            header.crc,
            header.data_length,
            header.data_offset,
            header.load_addr,
            header.exe_addr,
            header.header_sum,
            header.code_sum,
            header.next_header,
            header.isCompressed(),
            header.isValid(),
        });
        try writer.print(
            \\     app type: {s}
            \\   build date: {s}
            \\      version: {s}
            \\    copyright: {s}
            \\
        , .{ info.app_type, info.build_date, info.version, info.copyright });
    }

    pub fn decompress(self: *const Self, allocator: Allocator) ![]u8 {
        const reader = std.io.fixedBufferStream(self.contents[1..]).reader();
        var inflater = try std.compress.zlib.zlibStream(allocator, reader);
        defer inflater.deinit();
        return inflater.reader().readAllAlloc(allocator, std.math.maxInt(usize));
    }

    pub fn deinit(self: *Self) void {
        self.app_info.deinit();
        self.allocator.free(self.contents);
        self.contents = undefined;
    }
};

pub fn main() !void {
    const file = try std.fs.cwd().openFile("firmware.ld", .{});
    defer file.close();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();

    var image = try LdFile.fromFile(file, alloc);
    defer image.deinit();

    const out = std.io.getStdOut().writer();
    try image.print(out);

    if (!image.header.isCompressed())
        return;

    try out.print("decompressing...\n", .{});
    const bytes = try image.decompress(alloc);
    defer alloc.free(bytes);
    try out.print("decompressed data is {} bytes long\n", .{bytes.len});
}
