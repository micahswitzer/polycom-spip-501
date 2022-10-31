const std = @import("std");
const uc = @import("unicorn.zig");
const Engine = uc.Engine;
const ld = @import("fw.zig");

const APP_BIN = @embedFile("../firmware.bin");
const CS0_BIN = @embedFile("../CS0.bin");

const PAGE_SIZE: usize = 4095;
const LOAD_ADDR = 0x10004000;
const END_ADDR = 0x12000000; //0x10c00000;
const LOAD_SIZE = END_ADDR - LOAD_ADDR; //(FILE.len + PAGE_SIZE) & ~PAGE_SIZE;
const EXEC_ADDR = LOAD_ADDR;

const SP_INIT = 0;
// the code will add the load address to SP
const SP_LOAD = SP_INIT + LOAD_ADDR;
const SP_SIZE = 0x4000;
const SP_BASE = SP_LOAD - SP_SIZE;

extern fn udbserver(*uc.Engine, u16, usize) void;

inline fn alignUp(comptime addr: comptime_int) comptime_int {
    return (addr + PAGE_SIZE - 1) & ~PAGE_SIZE;
}

inline fn alignDown(comptime addr: comptime_int) comptime_int {
    return addr & ~PAGE_SIZE;
}

const CS0_BASE = 0;
const CS0_SIZE = 0x0080_0000;

fn regRead(engine: *uc.Engine, reg: c_int) u32 {
    return engine.regRead(reg, u32) catch unreachable;
}

fn printGprs(engine: *uc.Engine) void {
    std.log.err(
        \\REGISTERS:
        \\  PC = 0x{x:0>8}  LR = 0x{x:0>8}
        \\  SP = 0x{x:0>8}  FP = 0x{x:0>8}  IP = 0x{x:0>8}
        \\  R0 = 0x{x:0>8}  R1 = 0x{x:0>8}
        \\  R2 = 0x{x:0>8}  R3 = 0x{x:0>8}
        \\  R4 = 0x{x:0>8}  R5 = 0x{x:0>8}
        \\  R6 = 0x{x:0>8}  R7 = 0x{x:0>8}
    , .{
        regRead(engine, uc.c.UC_ARM_REG_PC),
        regRead(engine, uc.c.UC_ARM_REG_LR),
        regRead(engine, uc.c.UC_ARM_REG_SP),
        regRead(engine, uc.c.UC_ARM_REG_FP),
        regRead(engine, uc.c.UC_ARM_REG_IP),
        regRead(engine, uc.c.UC_ARM_REG_R0),
        regRead(engine, uc.c.UC_ARM_REG_R1),
        regRead(engine, uc.c.UC_ARM_REG_R2),
        regRead(engine, uc.c.UC_ARM_REG_R3),
        regRead(engine, uc.c.UC_ARM_REG_R4),
        regRead(engine, uc.c.UC_ARM_REG_R5),
        regRead(engine, uc.c.UC_ARM_REG_R6),
        regRead(engine, uc.c.UC_ARM_REG_R7),
    });
}

fn printStackTrace(engine: *Engine) void {
    var frame: [3]u32 = undefined;
    var fp = regRead(engine, uc.c.UC_ARM_REG_FP);
    var pc = regRead(engine, uc.c.UC_ARM_REG_PC);
    var it: usize = 1;
    while (fp != 0 and pc != 0 and it < 12) {
        engine.memRead(
            @intCast(u64, fp - @sizeOf(@TypeOf(frame))),
            std.mem.sliceAsBytes(frame[0..]),
        ) catch unreachable;
        std.log.info(
            \\FRAME [{}]
            \\  [0] 0x{x:0>8}
            \\  [1] 0x{x:0>8}
            \\  [2] 0x{x:0>8}
        , .{
            it,
            frame[0],
            frame[1],
            frame[2],
        });
        it += 1;
        pc = frame[2];
        fp = frame[0];
        std.log.err("0x{x:0>8} at 0x{x:0>8}", .{ pc, fp });
    }
}

fn memHookCb(
    engine: *uc.Engine,
    access_type: c_int,
    address: u64,
    size: c_int,
    value: u64,
    user_data: ?*anyopaque,
) callconv(.C) bool {
    _ = user_data;
    std.log.err(
        \\BAD ACCESS ({}) at 0x{x}
        \\       size = {}, value = 0x{x}
    , .{ access_type, address, size, value });
    printGprs(engine);
    printStackTrace(engine);
    engine.emuStop() catch unreachable;
    return true;
}

//const MmioRead = uc.Engine.CbMmioRead;
//const MmioWrite = uc.Engine.CbMmioWrite;

const MmioReadGeneric = *const fn (context: *anyopaque, engine: *Engine, offset: u32, size: u4) u32;
fn MmioRead(comptime T: type) type {
    return fn (context: *T, engine: *Engine, offset: u32, size: u4) u32;
}

const MmioWriteGeneric = *const fn (context: *anyopaque, engine: *Engine, offset: u32, size: u4, value: u32) void;
fn MmioWrite(comptime T: type) type {
    return fn (context: *T, engine: *Engine, offset: u32, size: u4, value: u32) void;
}

fn Invoker(comptime impl: anytype) type {
    return struct {
        const T = std.meta.Child(@TypeOf(impl));
        pub fn read(context: *anyopaque, engine: *Engine, offset: u32, size: u4) u32 {
            return T.read(@ptrCast(*T, @alignCast(@alignOf(T), context)), engine, offset, size);
        }
        pub fn write(context: *anyopaque, engine: *Engine, offset: u32, size: u4, value: u32) void {
            T.write(@ptrCast(*T, @alignCast(@alignOf(T), context)), engine, offset, size, value);
        }
    };
}

const Peripheral = struct {
    base: u32,
    size: u32,
    read_fn: MmioReadGeneric,
    write_fn: MmioWriteGeneric,
    context: *anyopaque,

    const Self = @This();

    pub fn read(self: *const Self, engine: *Engine, offset: u32, size: u4) u32 {
        return self.read_fn(self.context, engine, offset, size);
    }
    pub fn write(self: *const Self, engine: *Engine, offset: u32, size: u4, value: u32) void {
        self.write_fn(self.context, engine, offset, size, value);
    }

    pub fn create(context: anytype, base: u32, size: u32) Self {
        const invoker = Invoker(context);
        return Self{
            .base = base,
            .size = size,
            .read_fn = invoker.read,
            .write_fn = invoker.write,
            .context = @ptrCast(*anyopaque, context),
        };
    }
};

const UartContext = struct {
    const SCR = packed struct {
        fifo_ptr_access_enable: u1 = 0,
        _r0: u2 = 0,
        tx_empty_ctl_it: u1 = 0,
        rx_cts_wake_up_enable: u1 = 0,
        _r1: u1 = 0,
        fifo_init: u1 = 0,
        fifo_init_status: u1 = 0,
        //_r2: u16 = 0,

        const READ_MASK: u32 = 0b11011001;
        const WRITE_MASK: u32 = 0b01011001;

        pub fn as_raw(self: *const @This()) u32 {
            return @intCast(u32, @bitCast(u8, self.*));
        }
    };
    comptime {
        //@compileLog("SCR has bitsize", @bitSizeOf(SCR), "and bytesize", @sizeOf(SCR));
    }
    scr: SCR = .{},
    line_buf: [256]u8 = std.mem.zeroes([256]u8),
    line_idx: usize = 0,

    const Self = @This();

    pub fn read(self: *Self, engine: *Engine, offset: u32, size: u4) u32 {
        _ = engine;
        if (offset == 0xc and size == 4) {
            return self.scr.as_raw();
        }
        if (offset == 0x14)
            // say that we're always ready to transmit more data
            return 0b011_000_00;
        //std.log.info("UART READ:  offset = 0x{x:0>2}", .{offset});
        return 0;
    }
    pub fn write(self: *Self, engine: *Engine, offset: u32, size: u4, value: u32) void {
        _ = engine;
        _ = size;
        if (offset == 0xc) {
            const new_value = (self.scr.as_raw() & ~SCR.WRITE_MASK) | (value & SCR.WRITE_MASK);
            self.scr = @bitCast(SCR, @intCast(u8, new_value));
            self.scr.fifo_init_status = self.scr.fifo_init;
            return;
        }
        if (offset == 0x4) {
            const out = std.io.getStdOut().writer();
            const char = @intCast(u8, value);
            if (char == '\r' or self.line_idx == self.line_buf.len) {
                // flush
                _ = out.write(self.line_buf[0..self.line_idx]) catch 0;
                self.line_idx = 0;
            }
            self.line_buf[self.line_idx] = char;
            self.line_idx += 1;
            return;
        }
        //std.log.info("UART WRITE: offset = 0x{x:0>2}, value = 0x{x:0>8}", .{ offset, value });
    }
};
const NullPeriph = struct {
    _dummy: u8 = 0,
    const Self = @This();
    pub fn read(self: *Self, engine: *Engine, offset: u32, size: u4) u32 {
        _ = self;
        _ = engine;
        _ = offset;
        _ = size;
        return 0;
    }
    pub fn write(self: *Self, engine: *Engine, offset: u32, size: u4, value: u32) void {
        _ = self;
        _ = engine;
        _ = offset;
        _ = size;
        _ = value;
    }
};

var uart0 = UartContext{};
//var spi = NullPeriph{};
var cpu_info = (struct {
    const INFO: u32 = 0xaaaaaaab;
    _dummy: u8 = 0,
    const Self = @This();
    pub fn read(self: *Self, engine: *Engine, offset: u32, size: u4) u32 {
        _ = self;
        _ = engine;
        _ = offset;
        _ = size;
        return INFO;
    }
    pub fn write(self: *Self, engine: *Engine, offset: u32, size: u4, value: u32) void {
        _ = self;
        _ = engine;
        _ = offset;
        _ = size;
        _ = value;
    }
}){};

const PERIPHERALS = [_]Peripheral{
    Peripheral.create(&uart0, UART_BASE, UART_SIZE),
    //Peripheral.create(&spi, SPI_BASE, SPI_SIZE),
    Peripheral.create(&cpu_info, 0xffff_3100, 4),
};
fn get_peripheral(addr: u32) ?*const Peripheral {
    for (PERIPHERALS) |*p| {
        if (addr >= p.base and addr < (p.base + p.size))
            return p;
    }
    return null;
}

const MMIO_INFO: struct { start: u32, size: u32 } = blk: {
    var min_addr: ?u32 = null;
    var max_addr: ?u32 = null;
    for (PERIPHERALS) |*p| {
        if (min_addr) |a| {
            if (p.base < a) {
                min_addr = p.base;
            }
        } else {
            min_addr = p.base;
        }
        const end = p.base + p.size;
        if (max_addr) |a| {
            if (end > a) {
                max_addr = end;
            }
        } else {
            max_addr = end;
        }
    }

    const aligned_start: u32 = alignDown(min_addr.?);
    const aligned_size: u32 = alignUp(max_addr.? - aligned_start);

    break :blk .{ .start = aligned_start, .size = aligned_size };
};

const MMIO_BASE = MMIO_INFO.start;
const MMIO_SIZE = MMIO_INFO.size;

const UART_BASE = 0xffff_1000;
const UART_SIZE = 0x6c;

const SPI_BASE = 0xffff_2000;
const SPI_SIZE = 0x800;

const CPUINFO_BASE = 0xffff_3100;
const CPUINFO_SIZE = 4;

fn mmioRead(engine: *Engine, offset: u64, size: c_uint, user_data: ?*anyopaque) callconv(.C) u64 {
    _ = user_data;
    // okay to downcast here because we're working with a 32-bit address space
    const addr = MMIO_BASE + @intCast(u32, offset);
    if (get_peripheral(addr)) |p| {
        return @intCast(u64, p.read(engine, addr - p.base, @intCast(u4, size)));
    }
    std.log.info("READ  UNKNOWN PERIPHERAL: addr = 0x{x:0>8}, size = {}", .{ addr, size });
    return 0;
}
fn mmioWrite(engine: *Engine, offset: u64, size: c_uint, value: u64, user_data: ?*anyopaque) callconv(.C) void {
    _ = user_data;
    // okay to downcast here because we're working with a 32-bit address space
    const addr = MMIO_BASE + @intCast(u32, offset);
    if (get_peripheral(addr)) |p| {
        p.write(engine, addr - p.base, @intCast(u4, size), @intCast(u32, value));
        return;
    }
    std.log.info("WRITE UNKNOWN PERIPHERAL: addr = 0x{x:0>8}, size = {}, value = 0x{x}", .{ addr, size, value });
}

fn openFwImage() !void {
    //var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    //const alloc = gpa.allocator();
    //const alloc = std.heap.c_allocator;

    //std.log.info("Opening firmware image...", .{});
    //const file = try std.fs.cwd().openFile("firmware.ld", .{});
    //defer file.close();
    //var image = try ld.LdFile.fromFile(file, alloc);
    //defer image.deinit();
    //const out = std.io.getStdOut().writer();
    //try image.print(out);
}

pub fn main() anyerror!void {
    std.log.info("Creating engine...", .{});
    var engine = try uc.Engine.open(uc.Arch.Arm, uc.Mode.Arm | uc.Mode.LittleEndian);
    defer engine.close();

    {
        const alloc = std.heap.c_allocator;
        const args = try std.process.argsAlloc(alloc);
        defer std.process.argsFree(alloc, args);
        if (args.len != 3) {
            std.log.err("Incorrect number of arguments provided", .{});
            return;
        }
        const app_path = args[1];
        const flash_path = args[2];
        const cwd = comptime std.fs.cwd();
        const app_file = try cwd.openFileZ(app_path, .{});
        defer app_file.close();
        const flash_file = try cwd.openFileZ(flash_path, .{});
        defer flash_file.close();
        const app_data = try app_file.reader().readAllAlloc(alloc, 10 * 1000 * 1000);
        defer alloc.free(app_data);
        const flash_data = try flash_file.reader().readAllAlloc(alloc, 10 * 1000 * 1000);
        defer alloc.free(flash_data);

        // load firmware image
        try engine.memMap(LOAD_ADDR, LOAD_SIZE, uc.Prot.All);
        try engine.memWrite(LOAD_ADDR, app_data);
        try engine.regWrite(uc.c.UC_ARM_REG_PC, @as(u32, LOAD_ADDR));
        std.log.info("Loading APP at {x}-{x} ({x})", .{ LOAD_ADDR, LOAD_ADDR + LOAD_SIZE, LOAD_SIZE });

        // setup flash region
        try engine.memMap(CS0_BASE, CS0_SIZE, uc.Prot.Read | uc.Prot.Write);
        try engine.memWrite(CS0_BASE, flash_data);
    }

    // setup stack region
    try engine.memMap(SP_BASE, SP_SIZE, uc.Prot.Read | uc.Prot.Write);
    try engine.regWrite(uc.c.UC_ARM_REG_SP, @as(u32, SP_INIT));

    // setup SPI region
    //try engine.memMap(SPI_BASE, SPI_SIZE, uc.Prot.Read | uc.Prot.Write);

    // map the UART mmio region
    std.log.info("mapping in 0x{x} bytes of mmio at 0x{x:0>8}", .{ MMIO_SIZE, MMIO_BASE });
    try engine.mmioMap(MMIO_BASE, MMIO_SIZE, mmioRead, null, mmioWrite, null);

    // register callback
    // don't need to save return value because we'll never delete the hook
    _ = try engine.hookAddMem(memHookCb, null, 0, 0xffffffff);

    // connect to udbserver
    udbserver(engine, 1234, 0);

    std.log.info("Begining emulation...", .{});
    const res = engine.emuStart(EXEC_ADDR, 0x1002430c, 1000 * 1000 * 500, 0);
    if (res) {} else |err| {
        if (err != uc.Error.Map)
            return err;
        std.log.info("Ate MAP error", .{});
    }

    std.log.info("Done.", .{});
}
