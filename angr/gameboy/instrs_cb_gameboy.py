import logging
log = logging.getLogger(__name__)

import abc
from .arch_gameboy import ArchGameboy
from .instrs_gameboy import GameboyInstruction, bits_to_signed_int, bits_to_le16
from pyvex.lifting.util import Instruction, JumpKind, ParseError, Type
import bitstring
from bitstring import Bits
import struct


# Instruction block: 11001011 00000xxx
# Count: 8 instructions
class Instruction_RLC(GameboyInstruction):
    bin_format = '1100101100000rrr'
    name = 'RLC r8'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)
    
    def zero(self, *args):
        return args[-1] == 0

    def negative(self, *args):
        return 0
    
    def half_carry(self, *args):
        return 0

# Instruction block: 11001011 00001xxx
# Count: 8 instructions
class Instruction_RRC(GameboyInstruction):
    bin_format = '1100101100001rrr'
    name = 'RRC r8'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)
    
    def zero(self, *args):
        return args[-1] == 0

    def negative(self, *args):
        return 0
    
    def half_carry(self, *args):
        return 0

# Instruction block: 11001011 00010xxx
# Count: 8 instructions
class Instruction_RL(GameboyInstruction):
    bin_format = '1100101100010rrr'
    name = 'RL r8'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)
    
    def zero(self, *args):
        return args[-1] == 0

    def negative(self, *args):
        return 0
    
    def half_carry(self, *args):
        return 0

# Instruction block: 11001011 00011xxx
# Count: 8 instructions
class Instruction_RR(GameboyInstruction):
    bin_format = '1100101100011rrr'
    name = 'RR r8'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)
    
    def zero(self, *args):
        return args[-1] == 0

    def negative(self, *args):
        return 0
    
    def half_carry(self, *args):
        return 0

# Instruction block: 11001011 00100xxx
# Count: 8 instructions
class Instruction_SLA(GameboyInstruction):
    bin_format = '1100101100100rrr'
    name = 'SLA r8'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)
    
    def zero(self, *args):
        return args[-1] == 0
    
    def negative(self, *args):
        return 0
    
    def half_carry(self, *args):
        return 0

# Instruction block: 11001011 00101xxx
# Count: 8 instructions
class Instruction_SRA(GameboyInstruction):
    bin_format = '1100101100101rrr'
    name = 'SRA r8'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)
    
    def zero(self, *args):
        return args[-1] == 0

    def negative(self, *args):
        return 0
    
    def half_carry(self, *args):
        return 0

# Instruction block: 11001011 00110xxx
# Count: 8 instructions
class Instruction_SWAP(GameboyInstruction):
    bin_format = '1100101100110rrr'
    name = 'SWAP r8'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)
    
    def zero(self, *args):
        return args[-1] == 0

    def negative(self, *args):
        return 0
    
    def half_carry(self, *args):
        return 0

# Instruction block: 11001011 00111xxx
# Count: 8 instructions
class Instruction_SRL(GameboyInstruction):
    bin_format = '1100101100111rrr'
    name = 'SRL r8'

    def compute_result(self, *args):
        log.warn('Instruction %s semantics not implemented' % self.name)

    def zero(self, *args):
        return args[-1] == 0

    def negative(self, *args):
        return 0
    
    def half_carry(self, *args):
        return 0

# Instruction block: 11001011 01xxxxxx
# Count: 64 instructions
class Instruction_BIT(GameboyInstruction):
    bin_format = '1100101101iiirrr'
    name = 'BIT x,r8'

    def fetch_operands(self):
        idx = int(self.data['i'], 2)
        reg = self.get_r8_val(self.data['r'])
        return (idx, reg)

    def compute_result(self, *args):
        idx, reg = self.fetch_operands()
        return reg[idx]

    def commit_result(self, *args):
        self.put_r8_val(args[-1], self.data['r'])
    
    def zero(self, *args):
        return args[-1] == 0

    def negative(self, *args):
        return 0
    
    def half_carry(self, *args):
        return 1
    
# Instruction block: 11001011 10xxxxxx
# Count: 64 instructions
class Instruction_RES(GameboyInstruction):
    bin_format = '1100101110iiirrr'
    name = 'RES x,r8'
    
    def fetch_operands(self):
        idx = int(self.data['i'], 2)
        reg = self.get_r8_val(self.data['r'])
        return (idx, reg)

    def compute_result(self, *args):
        idx, reg = self.fetch_operands()
        reg.set_bit(idx, 0)
        return reg

    def commit_result(self, *args):
        self.put_r8_val(args[-1], self.data['r'])

# Instruction block: 11001011 11xxxxxx
# Count: 64 instructions
class Instruction_SET(GameboyInstruction):
    bin_format = '1100101111iiirrr'
    name = 'SET x,r8'

    def fetch_operands(self):
        idx = int(self.data['i'], 2)
        reg = self.get_r8_val(self.data['r'])
        return (idx, reg)

    def compute_result(self, *args):
        idx, reg = self.fetch_operands()
        reg.set_bit(idx, 1)
        return reg

    def commit_result(self, *args):
        self.put_r8_val(args[-1], self.data['r'])
