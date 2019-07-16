import logging
log = logging.getLogger(__name__)

import abc
from .arch_gameboy import ArchGameboy
from pyvex.lifting.util import Instruction, JumpKind, ParseError, Type
import bitstring
from bitstring import Bits
import struct

# Reference: https://www.pastraiser.com/cpu/gameboy/gameboy_opcodes.html
class GameboyInstruction(Instruction):
    opcode = None
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    # Default flag handling
    def zero(self, *args):
        #pylint: disable=unused-argument
        return None

    def negative(self, *args):
        #pylint: disable=unused-argument
        return None

    def carry(self, *args):
        #pylint: disable=unused-argument,no-self-use
        return None

    def half_carry(self, *args):
        #pylint: disable=unused-argument,no-self-use
        return None

    def get_f(self):
        return self.get('f', Type.int_8)

    def get_pc(self):
        return self.get('pc', Type.int_16)

    def put_f(self, val):
        return self.put(val, 'f')

    def get_carry(self):
        return self.get_f()[ArchGameboy.flags['CARRY']]

    def get_zero(self):
        return self.get_f()[ArchGameboy.flags['ZERO']]

    def get_negative(self):
        return self.get_f()[ArchGameboy.flags['NEGATIVE']]

    def get_half_carry(self):
        return self.get_f()[ArchGameboy.flags['HALF_CARRY']]

    SMALL_REGS = ['b','c','d','e','h','l','hl','a']
    def get_r8_val(self, bits):
        reg_idx = int(bits, 2)
        if reg_idx == 6: # (hl) case
            addr = self.get(self.SMALL_REGS[reg_idx], Type.int_16)
            return self.load(addr, Type.int_8)
        else:
            return self.get(self.SMALL_REGS[reg_idx], Type.int_8)
    
    def put_r8_val(self, bits):
        reg_idx = int(bits, 2)
        if reg_idx == 6:
            addr = self.get(self.SMALL_REGS[reg_idx], Type.int_16)
            return lambda val: self.store(val, addr)
        else:
            return lambda val: self.put(val, self.SMALL_REGS[reg_idx])
    
    BIG_REGS = ['bc', 'de', 'hl', 'sp']
    def put_r16_val(self, bits):
        reg_idx = int(bits, 2)
        return lambda val: self.put(val, self.BIG_REGS[reg_idx])
    
    def get_r16_val(self, bits):
        reg_idx = int(bits, 2)
        return lambda val: self.get(self.BIG_REGS[reg_idx], Type.int_16)

    def hldi_handling(self, diff):
        hl = self.get('hl', Type.int_16)
        hl += diff
        self.put(hl, 'hl')

    BIG_REGS_2 = ['bc', 'de', 'hl', 'hl']
    def get_r16_val_2(self, bits):
        reg_idx = int(bits, 2)
        value = self.get(self.BIG_REGS_2[reg_idx], Type.int_8)
        if reg_idx == 2:
            self.hldi_handling(1)
        elif reg_idx == 3:
            self.hldi_handling(-1)
        return value
            
    def put_r16_val_2(self, bits):
        reg_idx = int(bits, 2)
        def writer(val):
            addr = self.get(self.BIG_REGS_2[reg_idx], Type.int_16)
            self.store(val, addr)
            if reg_idx == 2:
                self.hldi_handling(1)
            elif reg_idx == 3:
                self.hldi_handling(-1)
        return writer

    def parse(self, bitstrm):
        return  Instruction.parse(self, bitstrm)

    def compute_flags(self, *args):
        """
        Compute the flags touched by each instruction
        and store them in the status register
        """
        z = self.zero(*args) # pylint: disable=assignment-from-none
        n = self.negative(*args) # pylint: disable=assignment-from-none
        h = self.half_carry(*args) # pylint: disable=assignment-from-none
        c = self.carry(*args) # pylint: disable=assignment-from-none
        
        self.set_flags(z, n, h, c)

    def set_flags(self, z, n, h, c):
        if not z and not n and not h and not c:
            return
        
        flags = [(z, ArchGameboy.flags['ZERO'], 'Z'),
                 (n, ArchGameboy.flags['NEGATIVE'], 'N'),
                 (h, ArchGameboy.flags['HALF_CARRY'], 'H'),
                 (c, ArchGameboy.flags['CARRY'], 'C')]

        freg = self.get_f()
        for flag, offset, _ in flags:
            if flag:
                freg = freg & ~(1 << offset) | (flag.cast_to(Type.int_8) << offset).cast_to(freg.ty)
        self.put_f(freg)

def bits_to_signed_int(s):
    return Bits(bin=s).int

def bits_to_le16(bits):
    return struct.unpack('<H', struct.pack('>H', int(bits,2)))[0]
