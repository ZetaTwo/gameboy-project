import abc
from .arch_gameboy import ArchGameboy
from pyvex.lifting.util import Instruction, JumpKind, ParseError, Type
import bitstring
from bitstring import Bits
import struct

import logging
log = logging.getLogger(__name__)


ZERO_BIT_IND = 7
NEGATIVE_BIT_IND = 6
HALF_CARRY_BIT_IND = 5
CARRY_BIT_IND = 4

# Reference: https://www.pastraiser.com/cpu/gameboy/gameboy_opcodes.html

class GameboyInstruction(Instruction):
    opcode = None
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.commit_func = None

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

    # Some common stuff we use around

    def get_f(self):
        return self.get('f', Type.int_8)

    def get_pc(self):
        return self.get('pc', Type.int_16)

    def put_f(self, val):
        return self.put(val, 'f')

    def get_carry(self):
        return self.get_f()[CARRY_BIT_IND]

    def get_zero(self):
        return self.get_f()[ZERO_BIT_IND]

    def get_negative(self):
        return self.get_f()[NEGATIVE_BIT_IND]

    def get_half_carry(self):
        return self.get_f()[HALF_CARRY_BIT_IND]

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

    def parse(self, bitstrm):
        return  Instruction.parse(self, bitstrm)

    def compute_flags(self, *args):
        """
        Compute the flags touched by each instruction
        and store them in the status register
        """
        z = self.zero(*args)
        n = self.negative(*args)
        h = self.half_carry(*args) # pylint: disable=assignment-from-no-return,assignment-from-none
        c = self.carry(*args) # pylint: disable=assignment-from-no-return,assignment-from-none
        
        self.set_flags(z, n, h, c)

    def set_flags(self, z, n, h, c):
        if not z and not n and not h and not c:
            return
        
        flags = [(z, ZERO_BIT_IND, 'Z'),
                 (n, NEGATIVE_BIT_IND, 'N'),
                 (h, HALF_CARRY_BIT_IND, 'H'),
                 (c, CARRY_BIT_IND, 'C')]

        freg = self.get_f()
        for flag, offset, _ in flags:
            if flag:
                freg = freg & ~(1 << offset) | (flag.cast_to(Type.int_8) << offset).cast_to(freg.ty)
        self.put_f(freg)

    ##
    ## Functions for dealing with MSP430's complex addressing modes
    ##

    def decorate_src(self, src_bits, mode_bits, imm_bits):
        """
        Computes the decorated source operand for disassembly
        """

        """
        src = ArchMSP430.register_index[int(src_bits, 2)]
        src_mode = int(mode_bits, 2)
        # Load the immediate word
        src_imm = None
        if imm_bits:
            src_imm = bits_to_signed_int(imm_bits)
        # Symbolic and Immediate modes use the PC as the source.
        if src == 'pc':
            if src_mode == ArchMSP430.Mode.INDEXED_MODE:
                src_mode = ArchMSP430.Mode.SYMBOLIC_MODE
            elif src_mode == ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE:
                src_mode = ArchMSP430.Mode.IMMEDIATE_MODE
        # Resolve the constant generator stuff.
        elif src == 'cg':
            if src_mode == ArchMSP430.Mode.REGISTER_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE0
            elif src_mode == ArchMSP430.Mode.INDEXED_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE1
            elif src_mode == ArchMSP430.Mode.INDIRECT_REGISTER_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE2
            else:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE_NEG1
        # If you use the SR as the source. things get weird.
        elif src == 'sr':
            if src_mode == ArchMSP430.Mode.INDEXED_MODE:
                src_mode = ArchMSP430.Mode.ABSOLUTE_MODE
            elif src_mode == ArchMSP430.Mode.INDIRECT_REGISTER_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE4
            elif src_mode == ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE8
        # Fetch constants
        if src_mode == ArchMSP430.Mode.CONSTANT_MODE0:
            src_str = "#0"
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE1:
            src_str = "#1"
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE2:
            src_str = "#2"
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE4:
            src_str = "#4"
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE8:
            src_str = "#8"
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE_NEG1:
            src_str = "#-1"
        # Fetch immediate.
        elif src_mode == ArchMSP430.Mode.IMMEDIATE_MODE:
            src_str = str(bits_to_signed_int(imm_bits))
        # Symbolic mode: Add the immediate to the PC
        elif src_mode == ArchMSP430.Mode.SYMBOLIC_MODE:
            src_str = "%s+%d" % (src, bits_to_signed_int(imm_bits))
        else:
            # Register mode can write-out to the source for one-operand, so set the writeout
            src_str = self.decorate_reg(src, src_mode, src_imm)
        return src_str
        """

    def fetch_src(self, src_bits, mode_bits, imm_bits, ty):
        """
        Fetch the ``source'' operand of an instruction.
        Returns the source as a VexValue, and, if it exists, a function for how it can be written
        to if needed (e.g., one-operand instructions)
        :param src_bits: bit-string of the src
        :param mode_bits: bit-string of the mode
        :param imm_bits: bit-string of the immediate
        :param ty: The type to use (the byte type or word type)
        :return: The src as a VexValue, and a lambda describing how to write to it if necessary
        """

        """
        src_num = int(src_bits, 2)
        src_name = ArchMSP430.register_index[src_num]
        src_mode = int(mode_bits, 2)
        writeout = None
        # Load the immediate word
        src_imm = None
        if imm_bits:
            src_imm = bits_to_signed_int(imm_bits)
        # Symbolic and Immediate modes use the PC as the source.
        if src_name == 'pc':
            if src_mode == ArchMSP430.Mode.INDEXED_MODE:
                src_mode = ArchMSP430.Mode.SYMBOLIC_MODE
            elif src_mode == ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE:
                src_mode = ArchMSP430.Mode.IMMEDIATE_MODE
        # Resolve the constant generator stuff.
        elif src_name == 'cg':
            if src_mode == ArchMSP430.Mode.REGISTER_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE0
            elif src_mode == ArchMSP430.Mode.INDEXED_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE1
            elif src_mode == ArchMSP430.Mode.INDIRECT_REGISTER_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE2
            else:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE_NEG1
        # If you use the SR as the source. things get weird.
        elif src_name == 'sr':
            if src_mode == ArchMSP430.Mode.INDEXED_MODE:
                src_mode = ArchMSP430.Mode.ABSOLUTE_MODE
            elif src_mode == ArchMSP430.Mode.INDIRECT_REGISTER_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE4
            elif src_mode == ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE:
                src_mode = ArchMSP430.Mode.CONSTANT_MODE8
        # Fetch constants
        if src_mode == ArchMSP430.Mode.CONSTANT_MODE0:
            src_vv = self.constant(0, ty)
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE1:
            src_vv = self.constant(1, ty)
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE2:
            src_vv = self.constant(2, ty)
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE4:
            src_vv = self.constant(4, ty)
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE8:
            src_vv = self.constant(8, ty)
        elif src_mode == ArchMSP430.Mode.CONSTANT_MODE_NEG1:
            src_vv = self.constant(-1, ty)
        # Fetch immediate.
        elif src_mode == ArchMSP430.Mode.IMMEDIATE_MODE:
            src_vv = self.constant(bits_to_signed_int(imm_bits), ty)
        # Symbolic mode: Add the immediate to the PC
        elif src_mode == ArchMSP430.Mode.SYMBOLIC_MODE:
            src_vv = self.get(src_num, Type.int_16) + bits_to_signed_int(imm_bits) + 2
        else:
            # Register mode can write-out to the source for one-operand, so set the writeout
            src_vv, writeout = self.fetch_reg(src_num, src_mode, src_imm, ty)
        return src_vv, writeout
        """

    def decorate_dst(self, dst_bits, mode_bits, imm_bits):
        """
        Computes the decorated destination operand for disassembly
        """

        """
        dst = ArchMSP430.register_index[int(dst_bits, 2)]
        dst_mode = int(mode_bits, 2)
        dst_imm = None
        # Using sr as the dst enables "absolute addressing"
        if dst == 'sr' and dst_mode == ArchMSP430.Mode.INDEXED_MODE:
            dst_mode = ArchMSP430.Mode.ABSOLUTE_MODE
        if imm_bits:
            dst_imm = bits_to_signed_int(imm_bits)

        # two-op instructions always have a dst
        dst_str = self.decorate_reg(dst, dst_mode, dst_imm)
        # val = val.cast_to(ty)
        return dst_str
        """

    def fetch_dst(self, dst_bits, mode_bits, imm_bits, ty):
        """
        Fetch the destination argument.
        :param dst_bits:
        :param mode_bits:
        :param imm_bits:
        :param ty:
        :return: The VexValue representing the destination, and the writeout function for it
        """

        """
        dst_num = int(dst_bits, 2)
        dst_name = ArchMSP430.register_index[dst_num]
        dst_mode = int(mode_bits, 2)
        dst_imm = None
        # Using sr as the dst enables "absolute addressing"
        if dst_name == 'sr' and dst_mode == ArchMSP430.Mode.INDEXED_MODE:
            dst_mode = ArchMSP430.Mode.ABSOLUTE_MODE
        if imm_bits:
            dst_imm = int(imm_bits, 2)

        # two-op instructions always have a dst and a writeout
        val, writeout = self.fetch_reg(dst_num, dst_mode, dst_imm, ty)
        # val = val.cast_to(ty)
        return val, writeout
        """

    def decorate_reg(self, reg_name, reg_mode, imm):
        # pylint: disable=no-self-use
        """
        Decorate the register argument used for disassembly
        """

        """
        # Boring register mode.  A write is just a Put.
        if reg_mode == ArchMSP430.Mode.REGISTER_MODE:
            reg_str = reg_name
        # Indexed mode, add the immediate to the register
        elif reg_mode == ArchMSP430.Mode.INDEXED_MODE:
            reg_str = "%d(%s)" % (imm, reg_name)
        # Indirect mode; fetch address in register; store is a write there.
        elif reg_mode == ArchMSP430.Mode.INDIRECT_REGISTER_MODE:
            reg_str = "@%s" % reg_str
        # Indirect Autoincrement mode. Increment the register by the type size, then access it
        elif reg_mode == ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE:
            reg_str = "@%s+" % reg_name
        elif reg_mode == ArchMSP430.Mode.ABSOLUTE_MODE:
            reg_str = imm
        else:
            raise Exception('Unknown mode found')
        return reg_str
        """

    def fetch_reg(self, reg_num, reg_mode, imm, ty):
        """
        Resolve the operand for register-based modes.
        :param reg_num: The Register Number
        :param reg_mode: The Register Mode
        :param imm: The immediate word, if any
        :param ty: The Type (byte or word)
        :return: The VexValue of the operand, and the writeout function, if any.
        """

        """
        # Boring register mode.  A write is just a Put.
        if reg_mode == ArchMSP430.Mode.REGISTER_MODE:
            # Fetch the register
            reg_vv = self.get(reg_num, ty)
            val = reg_vv
            writeout = lambda v: self.put(v.cast_to(REGISTER_TYPE), reg_num)
        # Indexed mode, add the immediate to the register
        # A write here is a store to reg + imm
        elif reg_mode == ArchMSP430.Mode.INDEXED_MODE:
            # Fetch the register
            reg_vv = self.get(reg_num, REGISTER_TYPE)
            addr_val = reg_vv + imm
            val = self.load(addr_val, ty)
            writeout = lambda v: self.store(v, addr_val)
        # Indirect mode; fetch address in register; store is a write there.
        elif reg_mode == ArchMSP430.Mode.INDIRECT_REGISTER_MODE:
            # Fetch the register
            reg_vv = self.get(reg_num, REGISTER_TYPE)
            val = self.load(reg_vv, ty)
            writeout = lambda v: self.store(v, reg_vv)
        # Indirect Autoincrement mode. Increment the register by the type size, then access it
        elif reg_mode == ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE:
            if ty == Type.int_16:
                incconst = self.constant(2, REGISTER_TYPE)
            else:
                incconst = self.constant(1, REGISTER_TYPE)
            # Fetch the register
            reg_vv = self.get(reg_num, REGISTER_TYPE)
            # Do the increment, now
            self.put(reg_vv + incconst, reg_num)
            # Now load it.
            val = self.load(reg_vv, ty)
            writeout = lambda v: self.store(v, reg_num)
        elif reg_mode == ArchMSP430.Mode.ABSOLUTE_MODE:
            imm_vv = self.constant(imm, REGISTER_TYPE)
            val = self.load(imm_vv, ty)
            writeout = lambda v: self.store(v, imm_vv)
        else:
            raise Exception('Unknown mode found')
        return val, writeout
        """

    # The TypeXInstruction classes will do this.
    @abc.abstractmethod
    def fetch_operands(self):
        return []


def bits_to_le16(bits):
    return struct.unpack('<H', struct.pack('>H', int(bits,2)))[0]

# Instruction group: NOP
class Instruction_NOP(GameboyInstruction):
    bin_format = '00000000'
    name = 'nop'

    def disassemble(self):
        return self.addr, self.name, []

    def compute_result(self, *args):
        pass

# Instruction group: jump
class Instruction_JPNZ(GameboyInstruction):
    bin_format = format(0xC2, '08b') + 'a'*16
    name = 'jpnz'

    def disassemble(self):
        return self.addr, self.name, [self.data['a']]

    def compute_result(self, *args):
        self.jump(self.get_zero() == 0, bits_to_le16(self.data['a']))

class Instruction_JP(GameboyInstruction):
    bin_format = format(0xC3, '08b') + 'a'*16
    name = 'jp'

    def disassemble(self):
        return self.addr, self.name, [self.data['a']]
    
    @abc.abstractmethod
    def compute_result(self, *args):
        self.jump(None, bits_to_le16(self.data['a']))

class Instruction_JPZ(GameboyInstruction):
    bin_format = format(0xCA, '08b') + 'a'*16
    name = 'jpz'

    def disassemble(self):
        return self.addr, self.name, [self.data['a']]

    def compute_result(self, *args):
        self.jump(self.get_zero() == 1, bits_to_le16(self.data['a']))

class Instruction_JPNC(GameboyInstruction):
    bin_format = format(0xD2, '08b') + 'a'*16
    name = 'jpnc'

    def disassemble(self):
        return self.addr, self.name, [self.data['a']]

    def compute_result(self, *args):
        self.jump(self.get_carry() == 0, bits_to_le16(self.data['a']))

class Instruction_JPC(GameboyInstruction):
    bin_format = format(0xDA, '08b') + 'a'*16
    name = 'jpc'

    def disassemble(self):
        return self.addr, self.name, [self.data['a']]

    def compute_result(self, *args):
        self.jump(self.get_carry() == 1, bits_to_le16(self.data['a']))

class Instruction_JPHL(GameboyInstruction):
    bin_format = format(0xE9, '08b')
    name = 'jphl'

    def disassemble(self):
        return self.addr, self.name, [self.data['a']]

    def compute_result(self, *args):
        self.jump(None, self.get('hl', Type.int_16))


# Generated
class Instruction_rlca(GameboyInstruction):
    bin_format = format(0x07, '08b')
    name = 'rlca'
class Instruction_rrca(GameboyInstruction):
    bin_format = format(0x0f, '08b')
    name = 'rrca'
class Instruction_stop(GameboyInstruction):
    bin_format = format(0x10, '08b')
    name = 'stop'
class Instruction_rla(GameboyInstruction):
    bin_format = format(0x17, '08b')
    name = 'rla'
class Instruction_rra(GameboyInstruction):
    bin_format = format(0x1f, '08b')
    name = 'rra'
class Instruction_daa(GameboyInstruction):
    bin_format = format(0x27, '08b')
    name = 'daa'
class Instruction_cpl(GameboyInstruction):
    bin_format = format(0x2f, '08b')
    name = 'cpl'
class Instruction_scf(GameboyInstruction):
    bin_format = format(0x37, '08b')
    name = 'scf'
class Instruction_ccf(GameboyInstruction):
    bin_format = format(0x3f, '08b')
    name = 'ccf'

class Instruction_adc(GameboyInstruction):
    bin_format = '10001ddd'
    name = 'adc'
"""
class Instruction_adc(GameboyInstruction):
    bin_format = format(0xce, '08b') + 'x'*8
    name = 'adc'
"""

class Instruction_sub(GameboyInstruction):
    bin_format = '10010ddd'
    name = 'sub'
"""
class Instruction_sub(GameboyInstruction):
    bin_format = format(0xd6, '08b') + 'x'*8
    name = 'sub'
"""


class Instruction_sbc(GameboyInstruction):
    bin_format = '10011ddd'
    name = 'sbc'

"""
class Instruction_sbc(GameboyInstruction):
    bin_format = format(0xde, '08b') + 'x'*8
    name = 'sbc'
"""

class Instruction_and(GameboyInstruction):
    bin_format = '10100ddd'
    name = 'and'
"""
class Instruction_and(GameboyInstruction):
    bin_format = format(0xe6, '08b') + 'x'*8
    name = 'and'

"""

class Instruction_xor(GameboyInstruction):
    bin_format = '10101ddd'
    name = 'xor'
"""
class Instruction_xor(GameboyInstruction):
    bin_format = format(0xee, '08b') + 'x'*8
    name = 'xor'
"""

class Instruction_or(GameboyInstruction):
    bin_format = '10110ddd'
    name = 'or'
"""
class Instruction_or(GameboyInstruction):
    bin_format = format(0xf6, '08b') + 'x'*8
    name = 'or'
"""


class Instruction_cp(GameboyInstruction):
    bin_format = '10111ddd'
    name = 'cp'
"""
class Instruction_cp(GameboyInstruction):
    bin_format = format(0xfe, '08b') + 'x'*8
    name = 'cp'
"""

class Instruction_rst(GameboyInstruction):
    bin_format = '11hhh111'
    name = 'rst'

class Instruction_push(GameboyInstruction):
    bin_format = '11ss0101'
    name = 'push'

class Instruction_call(GameboyInstruction):
    bin_format = format(0xc4, '08b') + 'x'*16
    name = 'call'
"""
class Instruction_call(GameboyInstruction):
    bin_format = format(0xcc, '08b') + 'x'*16
    name = 'call'
class Instruction_call(GameboyInstruction):
    bin_format = format(0xcd, '08b') + 'x'*16
    name = 'call'
class Instruction_call(GameboyInstruction):
    bin_format = format(0xd4, '08b') + 'x'*16
    name = 'call'
class Instruction_call(GameboyInstruction):
    bin_format = format(0xdc, '08b') + 'x'*16
    name = 'call'
"""

class Instruction_ret(GameboyInstruction):
    bin_format = format(0xc0, '08b')
    name = 'ret'
"""
class Instruction_ret(GameboyInstruction):
    bin_format = format(0xc8, '08b')
    name = 'ret'
class Instruction_ret(GameboyInstruction):
    bin_format = format(0xc9, '08b')
    name = 'ret'
class Instruction_ret(GameboyInstruction):
    bin_format = format(0xd0, '08b')
    name = 'ret'
class Instruction_ret(GameboyInstruction):
    bin_format = format(0xd8, '08b')
    name = 'ret'
class Instruction_reti(GameboyInstruction):
    bin_format = format(0xd9, '08b')
    name = 'reti'
"""

class Instruction_pop16(GameboyInstruction):
    bin_format = '11ss0001'
    name = 'pop'


class Instruction_di(GameboyInstruction):
    bin_format = format(0xf3, '08b')
    name = 'di'

class Instruction_ei(GameboyInstruction):
    bin_format = format(0xfb, '08b')
    name = 'ei'

class Instruction_inc_reg8(GameboyInstruction):
    bin_format = '00ddd100'
    name = 'inc reg'

class Instruction_inc_reg16(GameboyInstruction):
    bin_format = '00ss0011'
    name = 'inc'

class Instruction_dec_reg8(GameboyInstruction):
    bin_format = '00ddd101'
    name = 'dec reg'

class Instruction_dec_reg16(GameboyInstruction):
    bin_format = '00ss1011'
    name = 'dec'

class Instruction_add_reg16(GameboyInstruction):
    bin_format = '00ss1001'
    name = 'add HL, reg'

class Instruction_add_reg8(GameboyInstruction):
    bin_format = '10000sss'
    name = 'add A,reg'

"""
class Instruction_add(GameboyInstruction):
    bin_format = format(0xc6, '08b') + 'x'*8
    name = 'add'
class Instruction_add(GameboyInstruction):
    bin_format = format(0xe8, '08b') + 'x'*8
    name = 'add'
"""



"""
class Instruction_ld(GameboyInstruction):
    bin_format = format(0x01, '08b') + 'x'*16
    name = 'ld'
class Instruction_ld7(GameboyInstruction):
    bin_format = format(0x11, '08b') + 'x'*16
    name = 'ld'
class Instruction_ld12(GameboyInstruction):
    bin_format = format(0x21, '08b') + 'x'*16
    name = 'ld'
class Instruction_ld17(GameboyInstruction):
    bin_format = format(0x31, '08b') + 'x'*16
    name = 'ld'
"""

"""
class Instruction_ld2(GameboyInstruction):
    bin_format = format(0x02, '08b')
    name = 'ld'
class Instruction_ld8(GameboyInstruction):
    bin_format = format(0x12, '08b')
    name = 'ld'
class Instruction_ld13(GameboyInstruction):
    bin_format = format(0x22, '08b')
    name = 'ld'
class Instruction_ld18(GameboyInstruction):
    bin_format = format(0x32, '08b')
    name = 'ld'
"""

"""
class Instruction_ld3(GameboyInstruction):
    bin_format = format(0x06, '08b') + 'x'*8
    name = 'ld'
class Instruction_ld9(GameboyInstruction):
    bin_format = format(0x16, '08b') + 'x'*8
    name = 'ld'
class Instruction_ld14(GameboyInstruction):
    bin_format = format(0x26, '08b') + 'x'*8
    name = 'ld'
class Instruction_ld19(GameboyInstruction):
    bin_format = format(0x36, '08b') + 'x'*8
    name = 'ld'
"""

"""
class Instruction_ld4(GameboyInstruction):
    bin_format = format(0x08, '08b') + 'x'*16
    name = 'ld'
"""

"""
class Instruction_ld5(GameboyInstruction):
    bin_format = format(0x0a, '08b')
    name = 'ld'
class Instruction_ld10(GameboyInstruction):
    bin_format = format(0x1a, '08b')
    name = 'ld'
class Instruction_ld15(GameboyInstruction):
    bin_format = format(0x2a, '08b')
    name = 'ld'
class Instruction_ld20(GameboyInstruction):
    bin_format = format(0x3a, '08b')
    name = 'ld'
"""

"""
class Instruction_ld6(GameboyInstruction):
    bin_format = format(0x0e, '08b') + 'x'*8
    name = 'ld'
class Instruction_ld11(GameboyInstruction):
    bin_format = format(0x1e, '08b') + 'x'*8
    name = 'ld'
class Instruction_ld16(GameboyInstruction):
    bin_format = format(0x2e, '08b') + 'x'*8
    name = 'ld'
class Instruction_ld21(GameboyInstruction):
    bin_format = format(0x3e, '08b') + 'x'*8
    name = 'ld'
"""

class Instruction_halt(GameboyInstruction):
    bin_format = '01110110' # 0x76: ld (hl) (hl)
    name = 'halt'
class Instruction_ld_reg_reg(GameboyInstruction):
    bin_format = '01dddsss'
    name = 'ld reg reg'

"""
class Instruction_ld(GameboyInstruction):
    bin_format = format(0xe0, '08b') + 'x'*8
    name = 'ld'
class Instruction_ld(GameboyInstruction):
    bin_format = format(0xe2, '08b')
    name = 'ld'
class Instruction_ld(GameboyInstruction):
    bin_format = format(0xea, '08b') + 'x'*16
    name = 'ld'
class Instruction_ld(GameboyInstruction):
    bin_format = format(0xf0, '08b') + 'x'*8
    name = 'ld'
class Instruction_ld(GameboyInstruction):
    bin_format = format(0xf2, '08b')
    name = 'ld'
class Instruction_ld(GameboyInstruction):
    bin_format = format(0xf8, '08b') + 'x'*8
    name = 'ld'
class Instruction_ld(GameboyInstruction):
    bin_format = format(0xf9, '08b')
    name = 'ld'
class Instruction_ld(GameboyInstruction):
    bin_format = format(0xfa, '08b') + 'x'*16
    name = 'ld'
"""

class Instruction_jr(GameboyInstruction):
    bin_format = format(0x18, '08b') + 'x'*8
    name = 'jr'
"""
'00 011 000'
'00 100 000'
'00 101 000'
'00 110 000'
'00 111 000'

class Instruction_jr(GameboyInstruction):
    bin_format = format(0x20, '08b') + 'x'*8
    name = 'jr'
class Instruction_jr(GameboyInstruction):
    bin_format = format(0x28, '08b') + 'x'*8
    name = 'jr'
class Instruction_jr(GameboyInstruction):
    bin_format = format(0x30, '08b') + 'x'*8
    name = 'jr'
class Instruction_jr(GameboyInstruction):
    bin_format = format(0x38, '08b') + 'x'*8
    name = 'jr'
"""