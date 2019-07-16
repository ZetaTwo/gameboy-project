import logging
log = logging.getLogger(__name__)

import abc
from .arch_gameboy import ArchGameboy
from .instrs_gameboy import GameboyInstruction, bits_to_signed_int, bits_to_le16
from pyvex.lifting.util import Instruction, JumpKind, ParseError, Type
import bitstring
from bitstring import Bits
import struct

# Instruction block: 00xxx000
# Count: 1, 1, 1, 5 = 8 instructions
class Instruction_NOP(GameboyInstruction):
    bin_format = '00000000'
    name = 'NOP'

    def compute_result(self):
        return None

class Instruction_STOP(GameboyInstruction):
    """STOP instruction. Note that this is 1 byte and not 2."""
    bin_format = '00010000'
    name = 'STOP'

    def compute_result(self, *args):
        self.jump(None, 0x10000, JumpKind.Exit)
        return None

class Instruction_LD_A16_SP(GameboyInstruction):
    bin_format = '00001000' + 'a'*16
    name = 'LD (a16),SP'

    def fetch_operands(self):
        self.dst = self.constant(bits_to_le16(self.data['a']), Type.int_16)
        sp = self.get('sp', Type.int_8)
        return self.dst, sp

    def compute_result(self, dst, sp):
        return sp

    def commit_result(self, res):
        self.store(res, self.dst)


class Instruction_JR(GameboyInstruction):
    bin_format = '00vvv000aaaaaaaa'
    name = 'JR'

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
    bin_format = '00rr0001' + 'd'*16
    name = 'LD r16,d16'

    def fetch_operands(self):
        self.dst = self.put_r16_val(self.data['r'])
        data = bits_to_le16(self.data['d'])
        return self.dst, data

    def compute_result(self, dst, data):
        log.warn('Instruction %s flag semantics not implemented' % self.name)
        return self.constant(data, Type.int_16)
    
    def commit_result(self, res):
        self.dst(res)

# Instruction block: 00xxx010
# Count: 8 instructions
class Instruction_LD_REG16(GameboyInstruction):
    bin_format = '00rrd010'
    name = 'LD (r16),A'

    def fetch_operands(self):
        direction = int(self.data['d'], 2)
        if direction == 0:
            self.dst = self.put_r16_val_2(self.data['r'])
            value = self.get('a', Type.int_8)
        elif direction == 1:
            self.dst = lambda val: self.put(val, 'a')
            value = self.get_r16_val_2(self.data['r'])
        return self.dst, value

    def compute_result(self, dst, value):
        log.warn('Instruction %s semantics not implemented' % self.name)
        return value
    
    def commit_result(self, res):
        self.dst(res)

# Instruction block: 00xx0011
# Count: 4 instructions
class Instruction_INC_R16(GameboyInstruction):
    bin_format = '00ss0011'
    name = 'INC r16'

    def fetch_operands(self):
        self.dst = self.put_r16_val(self.data['ss'])
        value = self.get_r16_val(self.data['ss'])

        return self.dst, value

    def compute_result(self, dst, value):
        log.warn('Instruction %s semantics not implemented' % self.name)
        return value + 1
    
    def commit_result(self, res):
        self.dst(res)

# Instruction block: 00xxx100
# Count: 8 instructions
class Instruction_INC_R8(GameboyInstruction):
    bin_format = '00ddd100'
    name = 'INC r8'

    def fetch_operands(self):
        self.dst = self.put_r8_val(self.data['d'])
        value = self.get_r8_val(self.data['d'])
        return self.dst, value

    def compute_result(self, dst, value):
        log.warn('Instruction %s semantics not implemented' % self.name)
        return value + 1
    
    def commit_result(self, res):
        self.dst(res)
    
    def zero(self, dst, value, res):
        return res == self.constant(0, res.ty)

# Instruction block: 00xxx101
# Count: 8 instructions
class Instruction_DEC_R8(GameboyInstruction):
    bin_format = '00ddd101'
    name = 'DEC r8'

    def fetch_operands(self):
        self.dst = self.put_r8_val(self.data['d'])
        value = self.get_r8_val(self.data['d'])
        return self.dst, value

    def compute_result(self, dst, value):
        log.warn('Instruction %s semantics not implemented' % self.name)
        return value - 1
    
    def commit_result(self, res):
        self.dst(res)

    def zero(self, dst, value, res):
        return res == self.constant(0, res.ty)

# Instruction block: 00xxx110
# Count: 8 instructions
class Instruction_LD_D8(GameboyInstruction):
    bin_format = '00rrr110' + 'd'*8
    name = 'LD reg,d8'

    def fetch_operands(self):
        self.dst = self.put_r8_val(self.data['r'])
        data = int(self.data['d'], 2)
        return self.dst, data

    def compute_result(self, dst, data):
        log.warn('Instruction %s flag semantics not implemented' % self.name)
        return self.constant(data, Type.int_8)
    
    def commit_result(self, res):
        self.dst(res)

# Instruction block: 000xx111
# Count: 4 instructions
class Instruction_RA(GameboyInstruction):
    bin_format = '000vv111'
    name = 'R[LR](C)A'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)

# Instruction block: 000xx111
# Count: 4 instructions
class Instruction_DAA(GameboyInstruction):
    bin_format = '00100111'
    name = 'DAA'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)

class Instruction_CPL(GameboyInstruction):
    bin_format = '00101111'
    name = 'CPL'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)

class Instruction_SCF(GameboyInstruction):
    bin_format = '00110111'
    name = 'SCF'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)

class Instruction_CCF(GameboyInstruction):
    bin_format = '00111111'
    name = 'CCF'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)

# Instruction block: 00xx1001
# Count: 4 instructions
class Instruction_ADD_R16(GameboyInstruction):
    bin_format = '00ss1001'
    name = 'ADD HL,r16'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)

# Instruction block: 00xx1011
# Count: 4 instructions
class Instruction_DEC_R16(GameboyInstruction):
    bin_format = '00ss1011'
    name = 'DEC r16'

    def fetch_operands(self):
        self.dst = self.put_r16_val(self.data['ss'])
        value = self.get_r16_val(self.data['ss'])

        return self.dst, value

    def compute_result(self, dst, value):
        log.warn('Instruction %s semantics not implemented' % self.name)
        return value - 1
    
    def commit_result(self, res):
        self.dst(res)

# Instruction block: 01xxxxxx
# Count: 1+63 = 64 instructions
class Instruction_HALT(GameboyInstruction):
    bin_format = '01110110' # 0x76: ld (hl) (hl)
    name = 'HALT'

    def compute_result(self, *args):
        self.jump(None, 0x10000, JumpKind.Exit)
        return None

class Instruction_LD_R8_R8(GameboyInstruction):
    bin_format = '01dddsss'
    name = 'LD r8,r8'

    def fetch_operands(self):
        src = self.get_r8_val(self.data['s'])
        self.dst = self.put_r8_val(self.data['d'])
        return src, self.dst

    def compute_result(self, src, dst):
        return src

    def commit_result(self, res):
        self.dst(res)

# Instruction block: 110xx000
# Count: 4 instructions
class Instruction_RET_flag(GameboyInstruction):
    bin_format = '110ff000'
    name = 'RET f'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)

# Instruction block: 11xx0001
# Count: 4 instructions
class Instruction_POP_R16(GameboyInstruction):
    bin_format = '11ss0001'
    name = 'POP r16'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)

# Instruction block: 110xx010
# Count: 4 instructions
class Instruction_JP_flag(GameboyInstruction):
    bin_format = '110ff010' + 'a'*16
    name = 'JP f,a16'

    def fetch_operands(self):
        dst = self.constant(bits_to_le16(self.data['a']), Type.int_16)
        flag = int(self.data['f'], 2)
        return dst, flag

    def disassemble(self):
        return self.addr, self.name, [self.data['a']]

    def compute_result(self, dst, flag):
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
        return None

# Instruction block: 11000011
# Count: 1 instructions
class Instruction_JP(GameboyInstruction):
    bin_format = '11000011' + 'a'*16
    name = 'JP a16'

    def compute_result(self, *args):
        dst = self.constant(bits_to_le16(self.data['a']), Type.int_16)
        self.jump(None, dst)

# Instruction block: 11001101
# Count: 1 instructions
class Instruction_CALL(GameboyInstruction):
    bin_format = '11001101' + 'a'*16
    name = 'CALL a16'

    def compute_result(self, *args):
        dst = self.constant(bits_to_le16(self.data['a']), Type.int_16)
        self.jump(None, dst, jumpkind=JumpKind.Call)

# Instruction block: 110xx100
# Count: 4 instructions
class Instruction_CALL_flag(GameboyInstruction):
    bin_format = '110ff100' + 'a'*16
    name = 'CALL f,a16'

    def disassemble(self):
        return self.addr, self.name, [self.data['a']]

    def compute_result(self, *args):
        dst = self.constant(bits_to_le16(self.data['a']), Type.int_16)
        flag = int(self.data['f'], 2)
        if flag == 0:
            self.jump(self.get_zero() == 0, dst, jumpkind=JumpKind.Call)
        elif flag == 1:
            self.jump(self.get_zero() == 1, dst, jumpkind=JumpKind.Call)
        elif flag == 2:
            self.jump(self.get_carry() == 0, dst, jumpkind=JumpKind.Call)
        elif flag == 3:
            self.jump(self.get_carry() == 1, dst, jumpkind=JumpKind.Call)
        else:
            raise ValueError('Variant %d not supported' % flag)

# Instruction block: 11xx0101
# Count: 4 instructions
class Instruction_PUSH(GameboyInstruction):
    bin_format = '11ss0101'
    name = 'PUSH'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)

# Instruction block: 11xxx111
# Count: 8 instructions
class Instruction_RST(GameboyInstruction):
    bin_format = '11hhh111'
    name = 'RST'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)

# Instruction block: 110x1001
# Count: 2 instructions
class Instruction_RET(GameboyInstruction):
    bin_format = '110v1001'
    name = 'RET'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)

# Instruction block: 11xxx110
# Count: 8 instructions
class Instruction_OP_D8(GameboyInstruction):
    bin_format = '11ooo110'
    name = 'ARITH d8'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)

# Instruction block: 11110011
# Count: 1 instructions
class Instruction_DI(GameboyInstruction):
    bin_format = '11110011'
    name = 'DI'

    def compute_result(self, *args):
        addr = self.constant(0xFFFF, Type.int_16)
        self.store(self.constant(0, Type.int_8), addr)

# Instruction block: 11111011
# Count: 1 instructions
class Instruction_EI(GameboyInstruction):
    bin_format = '11111011'
    name = 'EI'

    def compute_result(self, *args):
        addr = self.constant(0xFFFF, Type.int_16)
        self.put(self.constant(1, Type.int_8), addr)

# Instruction block: 11101000
# Count: 1 instructions
class Instruction_ADD_SP_R8(GameboyInstruction):
    bin_format = '11101000' + 'd'*8
    name = 'ADD SP,s8'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)

# Instruction block: 11101001
# Count: 1 instructions
class Instruction_JP_HL(GameboyInstruction):
    bin_format = '11101001'
    name = 'JP (HL)'

    def disassemble(self):
        return self.addr, self.name, [self.data['a']]

    def compute_result(self, *args):
        self.jump(None, self.get('hl', Type.int_16)) #TODO: incorrect

# Instruction block: 11111000
# Count: 1 instructions
class Instruction_LD_HL_SP_R8(GameboyInstruction):
    bin_format = '11111000' + 'd'*8
    name = 'LD HL,SP+s8'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)

# Instruction block: 11111001
# Count: 1 instructions
class Instruction_LD_SP_HL(GameboyInstruction):
    bin_format = '11111001'
    name = 'LD SP,HL'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)

# Instruction block: 111x0000
# Count: 2 instructions
class Instruction_LD_ACC_A8(GameboyInstruction):
    bin_format = '111d0000' + 'a'*8
    name = 'LD (a8)<->A'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)

# Instruction block: 111x0010
# Count: 2 instructions
class Instruction_LD_RC_ACC(GameboyInstruction):
    bin_format = '111d0010'
    name = 'LD (C)<->A'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)

# Instruction block: 111x1010
# Count: 2 instructions
class Instruction_ld(GameboyInstruction):
    bin_format = '111d1010' + 'a'*16
    name = 'LD (a16)<->A'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)
