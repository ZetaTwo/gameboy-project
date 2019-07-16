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
    BIG_REGS = ['bc', 'de', 'hl', 'af']
    
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

    """
    def commit_result(self, res):
        #pylint: disable=not-callable
        if self.commit_func is not None:
            self.commit_func(res)

    def match_instruction(self, data, bitstrm):
        # NOTE: The matching behavior for instructions is a "try-them-all-until-it-fits" approach.
        # Static bits are already checked, so we just look for the opcode.
        if data['o'] != self.opcode:
            raise ParseError("Invalid opcode, expected %s, got %s" % (self.opcode, data['o']))
        return True
    """

    SMALL_REGS = ['b','c','d','e','h','l','hl','a']
    def get_r8_val(self, bits):
        reg_idx = int(bits, 2)
        if reg_idx == 6: # (hl) case
            addr = self.get(self.SMALL_REGS[reg_idx], Type.int_16)
            return self.load(addr, Type.int_8)
        else:
            return self.get(self.SMALL_REGS[reg_idx], Type.int_8)
    
    def put_r8_val(self, bits, val):
        reg_idx = int(bits, 2)
        if reg_idx == 6:
            addr = self.get(self.SMALL_REGS[reg_idx], Type.int_16)
            return self.store(val, addr)
        else:
            return self.put(val, self.SMALL_REGS[reg_idx])

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
