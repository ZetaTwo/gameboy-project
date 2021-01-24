import struct
import traceback

from .gameboy import LR35902

from binaryninja import Type
from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.enums import SegmentFlag, SectionSemantics, SymbolType
from binaryninja.log import log_error, log_info
from binaryninja.types import Symbol

class GameboyRomView(BinaryView):
    name = 'Gameboy'
    long_name = 'Bameboy ROM'

    ROM_SIG_OFFSET = 0x104
    ROM_SIG_LEN = 0x30
    ROM_SIG = b"\xCE\xED\x66\x66\xCC\x0D\x00\x0B\x03\x73\x00\x83\x00\x0C\x00\x0D\x00\x08\x11\x1F\x88\x89\x00\x0E\xDC\xCC\x6E\xE6\xDD\xDD\xD9\x99\xBB\xBB\x67\x63\x6E\x0E\xEC\xCC\xDD\xDC\x99\x9F\xBB\xB9\x33\x3E"
    HDR_OFFSET = 0x134
    HDR_SIZE = 0x1C
    START_ADDR = 0x100
    ROM0_SIZE = 0x4000
    ROM0_OFFSET = 0
    ROM1_SIZE = 0x4000
    ROM1_OFFSET = 0x4000

    # (name, address, length)
    RAM_SEGMENTS = [
        ('VRAM', 0x8000, 0x2000),
        ('RAM1', 0xA000, 0x2000),
        ('RAM0', 0xC000, 0x2000),
        ('ECHO', 0xE000, 0x1E00),
        ('OAM',  0xFE00, 0xA0),
        # Unusuable RAM
        ('VOID', 0xFEA0, 0x60),
        ('IO',   0xFF00, 0x80),
        ('HRAM', 0xFF80, 0x80),
    ]    

    INTERRUPT_HANDLERS = [
        ('isr_usr0', 0x00),
        ('isr_usr1', 0x08),
        ('isr_usr2', 0x10),
        ('isr_usr3', 0x18),
        ('isr_usr4', 0x20),
        ('isr_usr5', 0x28),
        ('isr_usr6', 0x30),
        ('isr_usr7', 0x38),
        ('isr_vblank', 0x40),
        ('isr_lcd', 0x48),
        ('isr_timer', 0x50),
        ('isr_serial', 0x58),
        ('isr_joypad', 0x60),
    ]

    def __init__(self, data):
        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
        self.platform = Architecture[LR35902.name].standalone_platform
        self.raw = data

    @classmethod
    def is_valid_for_data(self, data):
        rom_sig = data.read(self.ROM_SIG_OFFSET, self.ROM_SIG_LEN)
        if rom_sig != self.ROM_SIG:
            return False
        hdr = data.read(self.HDR_OFFSET, self.HDR_SIZE)
        if len(hdr) < self.HDR_SIZE:
            return False
        return True

    def init(self):
        try:
            hdr = self.parent_view.read(self.HDR_OFFSET, self.HDR_SIZE)
            self.rom_title = hdr[0:15]
            self.color = hdr[15]
            self.licensee_code = struct.unpack("H", hdr[16:18])[0]
            self.gb_type = hdr[18]
            self.cart_type = hdr[19]
            self.rom_banks = hdr[20]
            self.ram_banks = hdr[21]
            self.destination_code = hdr[22]
            self.old_licensee_code = hdr[23]
            self.mask_rom_version = hdr[24]
            self.complement_check = hdr[25]
            self.checksum = struct.unpack("H", hdr[26:])[0]
        except:
            log_error(traceback.format_exc())
            return False
            
        # Add ROM mappings
        # ROM0
        self.add_auto_segment(self.ROM0_OFFSET, self.ROM0_SIZE, self.ROM0_OFFSET, self.ROM0_SIZE, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
        self.add_auto_section("ROM0", self.ROM0_OFFSET, self.ROM0_SIZE, SectionSemantics.ReadOnlyCodeSectionSemantics)
        # ROM1
        self.add_auto_segment(self.ROM1_OFFSET, self.ROM1_SIZE, self.ROM1_OFFSET, self.ROM1_SIZE, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
        self.add_auto_section("ROM1", self.ROM1_OFFSET, self.ROM1_SIZE, SectionSemantics.ReadWriteDataSectionSemantics)
        
        # Add RAM mappings
        for _, address, length in self.RAM_SEGMENTS:
            self.add_auto_segment(address, length, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable)

        # Add IO registers
        for address, name in LR35902.IO_REGISTERS.items():
            self.define_auto_symbol_and_var_or_function(Symbol(SymbolType.DataSymbol, address, name), Type.int(1))

        # Define entrypoint
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.START_ADDR, "_start"))
        self.add_entry_point(self.START_ADDR)

        # Define interrupts
        for name, address in self.INTERRUPT_HANDLERS:
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, address, name))
            #self.define_auto_symbol_and_var_or_function(Symbol(SymbolType.FunctionSymbol, address, name), Type.function(Type.void(), []))

        return True


    def perform_is_valid_offset(self, addr):
        # valid ROM addresses are the upper-half of the address space
        if addr >= 0 and addr < 0x8000:
            return True
        return False

    def perform_get_start(self):
        return 0

    def perform_get_length(self):
        return 0x10000

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.START_ADDR
