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
        z = self.zero(*args) # pylint: disable=assignment-from-none
        n = self.negative(*args) # pylint: disable=assignment-from-none
        h = self.half_carry(*args) # pylint: disable=assignment-from-none
        c = self.carry(*args) # pylint: disable=assignment-from-none
        
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

    # The TypeXInstruction classes will do this.
    @abc.abstractmethod
    def fetch_operands(self):
        return []

def bits_to_signed_int(s):
    return Bits(bin=s).int

def bits_to_le16(bits):
    return struct.unpack('<H', struct.pack('>H', int(bits,2)))[0]


# Instruction block: 00xxx000
# Count: 1, 1, 1, 5 = 8 instructions
class Instruction_NOP(GameboyInstruction):
    bin_format = '00000000'
    name = 'NOP'

    def disassemble(self):
        return self.addr, self.name, []

    @abc.abstractmethod
    def compute_result(self, *args):
        pass
class Instruction_STOP(GameboyInstruction):
    """STOP instruction. Note that this is 1 byte and not 2."""
    bin_format = '00010000'
    name = 'STOP'
class Instruction_LD_A16_SP(GameboyInstruction):
    bin_format = '00001000'
    name = 'LD (a16),SP'
class Instruction_JR(GameboyInstruction):
    bin_format = '00vvv000aaaaaaaa'
    name = 'JR'

    @abc.abstractmethod
    def compute_result(self, *args):
        variant = int(self.data['v'], 2) - 0b11
        offset = bits_to_signed_int(self.data['a'])
        pc = self.get_pc()
        dst = pc + offset
        if variant == 0:
            self.jump(None, dst)
        elif variant == 1:
            self.jump(self.get_zero() == 0, dst)
        elif variant == 2:
            self.jump(self.get_zero() == 1, dst)
        elif variant == 3:
            self.jump(self.get_carry() == 0, dst)
        elif variant == 4:
            self.jump(self.get_carry() == 1, dst)
        else:
            raise ValueError('Variant %d not covered.' % variant)

# Instruction block: 00xx0001
# Count: 4 instructions
class Instruction_LD_D16(GameboyInstruction):
    bin_format = '00rr0001dddddddddddddddd'
    name = 'LD r16,d16'

# Instruction block: 00xx0010
# Count: 4 instructions
class Instruction_LD_REG16(GameboyInstruction):
    bin_format = '00rrd010'
    name = 'LD (r16),A'

# Instruction block: 00xx0011
# Count: 4 instructions
class Instruction_INC_R16(GameboyInstruction):
    bin_format = '00ss0011'
    name = 'INC r16'

# Instruction block: 00xxx100
# Count: 8 instructions
class Instruction_INC_R8(GameboyInstruction):
    bin_format = '00ddd100'
    name = 'INC r8'

# Instruction block: 00xxx101
# Count: 8 instructions
class Instruction_DEC_R8(GameboyInstruction):
    bin_format = '00ddd101'
    name = 'DEC r8'

# Instruction block: 00xxx110
# Count: 8 instructions
class Instruction_LD_D8(GameboyInstruction):
    bin_format = '00rrr110dddddddd'
    name = 'LD reg,d8'

# Instruction block: 000xx111
# Count: 4 instructions
class Instruction_RA(GameboyInstruction):
    bin_format = '000vv111'
    name = 'R[LR](C)A'

# Instruction block: 000xx111
# Count: 4 instructions
class Instruction_DAA(GameboyInstruction):
    bin_format = '00100111'
    name = 'DAA'
class Instruction_CPL(GameboyInstruction):
    bin_format = '00101111'
    name = 'CPL'
class Instruction_SCF(GameboyInstruction):
    bin_format = '00110111'
    name = 'SCF'
class Instruction_CCF(GameboyInstruction):
    bin_format = '00111111'
    name = 'CCF'

# Instruction block: 00xx1001
# Count: 4 instructions
class Instruction_ADD_R16(GameboyInstruction):
    bin_format = '00ss1001'
    name = 'ADD HL,r16'

# TODO: 0x0A, 0x1A, 0x2A, 0x3A

# Instruction block: 00xx1011
# Count: 4 instructions
class Instruction_DEC_R16(GameboyInstruction):
    bin_format = '00ss1011'
    name = 'DEC r16'

# Instruction block: 01xxxxxx
# Count: 1+63 = 64 instructions
class Instruction_HALT(GameboyInstruction):
    bin_format = '01110110' # 0x76: ld (hl) (hl)
    name = 'HALT'
class Instruction_LD_R8_R8(GameboyInstruction):
    bin_format = '01dddsss'
    name = 'LD r8,r8'

# Instruction block: 10000xxx
# Count: 8 instructions
class Instruction_ADD_R8(GameboyInstruction):
    bin_format = '10000sss'
    name = 'ADD A,r8'

# Instruction block: 10001xxx
# Count: 8 instructions
class Instruction_ADC_R8(GameboyInstruction):
    bin_format = '10001ddd'
    name = 'ADC A,r8'

# Instruction block: 10010xxx
# Count: 8 instructions
class Instruction_SUB_R8(GameboyInstruction):
    bin_format = '10010ddd'
    name = 'SUB A,r8'

# Instruction block: 10011xxx
# Count: 8 instructions
class Instruction_SBC_R8(GameboyInstruction):
    bin_format = '10011ddd'
    name = 'SBC A,r8'

# Instruction block: 10100xxx
# Count: 8 instructions
class Instruction_AND_R8(GameboyInstruction):
    bin_format = '10100ddd'
    name = 'AND A,r8'

# Instruction block: 10101xxx
# Count: 8 instructions
class Instruction_XOR_R8(GameboyInstruction):
    bin_format = '10101ddd'
    name = 'XOR A,r8'

# Instruction block: 10110xxx
# Count: 8 instructions
class Instruction_OR_R8(GameboyInstruction):
    bin_format = '10110ddd'
    name = 'OR A,r8'

# Instruction block: 10111xxx
# Count: 8 instructions
class Instruction_CP_R8(GameboyInstruction):
    bin_format = '10111ddd'
    name = 'CP'

# Instruction block: 110xx000
# Count: 4 instructions
class Instruction_RET_flag(GameboyInstruction):
    bin_format = '110ff000'
    name = 'RET f'

# Instruction block: 11xx0001
# Count: 4 instructions
class Instruction_POP_R16(GameboyInstruction):
    bin_format = '11ss0001'
    name = 'POP r16'

# Instruction block: 110xx010
# Count: 4 instructions
class Instruction_JP_flag(GameboyInstruction):
    bin_format = '110ff010aaaaaaaaaaaaaaaa'
    name = 'JP f'

    def disassemble(self):
        return self.addr, self.name, [self.data['a']]

    def compute_result(self, *args):
        dst = bits_to_le16(self.data['a'])
        flag = int(self.data['f'], 2)
        if flag == 0:
            self.jump(self.get_zero() == 0, dst)
        elif flag == 1:
            self.jump(self.get_zero() == 1, dst)
        elif flag == 2:
            self.jump(self.get_carry() == 0, dst)
        elif flag == 3:
            self.jump(self.get_carry() == 1, dst)
        else:
            raise ValueError('Variant %d not supported' % flag)

# TODO: 0xC3, CD

# Instruction block: 110xx100
# Count: 4 instructions
class Instruction_CALL_flag(GameboyInstruction):
    bin_format = '110ff100aaaaaaaaaaaaaaaa'
    name = 'CALL f,a16'

    def disassemble(self):
        return self.addr, self.name, [self.data['a']]

    def compute_result(self, *args):
        dst = bits_to_le16(self.data['a'])
        flag = int(self.data['f'], 2)
        if flag == 0:
            self.jump(self.get_zero() == 0, dst, jumpkind=JumpKind.call)
        elif flag == 1:
            self.jump(self.get_zero() == 1, dst, jumpkind=JumpKind.call)
        elif flag == 2:
            self.jump(self.get_carry() == 0, dst, jumpkind=JumpKind.call)
        elif flag == 3:
            self.jump(self.get_carry() == 1, dst, jumpkind=JumpKind.call)
        else:
            raise ValueError('Variant %d not supported' % flag)

# Instruction block: 11xx0101
# Count: 4 instructions
class Instruction_PUSH(GameboyInstruction):
    bin_format = '11ss0101'
    name = 'PUSH'

# TODO: <op> A,d8

# Instruction block: 11xxx111
# Count: 8 instructions
class Instruction_RST(GameboyInstruction):
    bin_format = '11hhh111'
    name = 'RST'

# Instruction block: 11xxx110
# Count: 8 instructions
class Instruction_OP_D8(GameboyInstruction):
    bin_format = '11ooo110'
    name = 'ARITH d8'

# TODO: Unorganized below


class Instruction_JPHL(GameboyInstruction):
    bin_format = format(0xE9, '08b')
    name = 'jphl'

    def disassemble(self):
        return self.addr, self.name, [self.data['a']]

    def compute_result(self, *args):
        self.jump(None, self.get('hl', Type.int_16))

"""
class Instruction_ret(GameboyInstruction):
    bin_format = format(0xc9, '08b')
    name = 'ret'

class Instruction_reti(GameboyInstruction):
    bin_format = format(0xd9, '08b')
    name = 'reti'
"""



class Instruction_di(GameboyInstruction):
    bin_format = format(0xf3, '08b')
    name = 'di'

class Instruction_ei(GameboyInstruction):
    bin_format = format(0xfb, '08b')
    name = 'ei'

"""

class Instruction_add(GameboyInstruction):
    bin_format = format(0xe8, '08b') + 'x'*8
    name = 'add'

class Instruction_ld4(GameboyInstruction):
    bin_format = format(0x08, '08b') + 'x'*16
    name = 'ld'
"""

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
    bin_format = format(0xfa, '08b') + 'x'*16
    name = 'ld'


class Instruction_ld(GameboyInstruction):
    bin_format = format(0xf8, '08b') + 'x'*8
    name = 'ld'
class Instruction_ld(GameboyInstruction):
    bin_format = format(0xf9, '08b')
    name = 'ld'
"""

# Instruction block: 11001011 00000xxx
# Count: 8 instructions
class Instruction_RLC(GameboyInstruction):
    bin_format = '11001011 00000rrr'
    name = 'RLC r8'

# Instruction block: 11001011 00001xxx
# Count: 8 instructions
class Instruction_RRC(GameboyInstruction):
    bin_format = '11001011 00001rrr'
    name = 'RRC r8'

# Instruction block: 11001011 00010xxx
# Count: 8 instructions
class Instruction_RL(GameboyInstruction):
    bin_format = '11001011 00010rrr'
    name = 'RL r8'

# Instruction block: 11001011 00011xxx
# Count: 8 instructions
class Instruction_RR(GameboyInstruction):
    bin_format = '11001011 00011rrr'
    name = 'RR r8'

# Instruction block: 11001011 00100xxx
# Count: 8 instructions
class Instruction_SLA(GameboyInstruction):
    bin_format = '11001011 00100rrr'
    name = 'SLA r8'

# Instruction block: 11001011 00101xxx
# Count: 8 instructions
class Instruction_SRA(GameboyInstruction):
    bin_format = '11001011 00101rrr'
    name = 'SRA r8'

# Instruction block: 11001011 00110xxx
# Count: 8 instructions
class Instruction_SWAP(GameboyInstruction):
    bin_format = '11001011 00110rrr'
    name = 'SWAP r8'

# Instruction block: 11001011 00111xxx
# Count: 8 instructions
class Instruction_SRL(GameboyInstruction):
    bin_format = '11001011 00111rrr'
    name = 'SRL r8'

# Instruction block: 11001011 01xxxxxx
# Count: 64 instructions
class Instruction_BIT(GameboyInstruction):
    bin_format = '11001011 01iiirrr'
    name = 'BIT x,r8'

# Instruction block: 11001011 10xxxxxx
# Count: 64 instructions
class Instruction_RES(GameboyInstruction):
    bin_format = '11001011 10iiirrr'
    name = 'RES x,r8'

# Instruction block: 11001011 11xxxxxx
# Count: 64 instructions
class Instruction_SET(GameboyInstruction):
    bin_format = '11001011 11iiirrr'
    name = 'SET x,r8'