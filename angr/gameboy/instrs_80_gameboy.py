import logging
log = logging.getLogger(__name__)

import abc
from .arch_gameboy import ArchGameboy
from .instrs_gameboy import GameboyInstruction, bits_to_signed_int, bits_to_le16
from pyvex.lifting.util import Instruction, JumpKind, ParseError, Type
import bitstring
from bitstring import Bits
import struct

# Meta block: 10oooxxx
# Count: 64 instructions
class ArithmethicInstruction(GameboyInstruction):
    def fetch_operands(self):
        a = self.get('a', Type.int_8)
        reg = self.get_r8_val(self.data['s'])
        return a, reg
    
    def commit_result(self, res):
        self.put(res, 'a')

    def zero(self, a, reg, res):
        return res == self.constant(0, res.ty)

# Instruction block: 10000xxx
# Count: 8 instructions
class Instruction_ADD_R8(ArithmethicInstruction):
    bin_format = '10000sss'
    name = 'ADD A,r8'

    def compute_result(self, a, reg):
        log.warn('Instruction %s flag semantics not implemented' % self.name)
        return a + reg

# Instruction block: 10001xxx
# Count: 8 instructions
class Instruction_ADC_R8(ArithmethicInstruction):
    bin_format = '10001sss'
    name = 'ADC A,r8'

    def compute_result(self, a, reg):
        log.warn('Instruction %s flag semantics not implemented' % self.name)
        return a + reg

# Instruction block: 10010xxx
# Count: 8 instructions
class Instruction_SUB_R8(ArithmethicInstruction):
    bin_format = '10010sss'
    name = 'SUB A,r8'

    def compute_result(self, a, reg):
        log.warn('Instruction %s flag semantics not implemented' % self.name)
        return a - reg

# Instruction block: 10011xxx
# Count: 8 instructions
class Instruction_SBC_R8(ArithmethicInstruction):
    bin_format = '10011sss'
    name = 'SBC A,r8'

    def compute_result(self, a, reg):
        log.warn('Instruction %s flag semantics not implemented' % self.name)
        return a - reg

# Instruction block: 10100xxx
# Count: 8 instructions
class Instruction_AND_R8(ArithmethicInstruction):
    bin_format = '10100sss'
    name = 'AND A,r8'

    def compute_result(self, a, reg):
        log.warn('Instruction %s flag semantics not implemented' % self.name)
        return a & reg

# Instruction block: 10101xxx
# Count: 8 instructions
class Instruction_XOR_R8(ArithmethicInstruction):
    bin_format = '10101sss'
    name = 'XOR A,r8'

    def compute_result(self, a, reg):
        log.warn('Instruction %s flag semantics not implemented' % self.name)
        return a ^ reg

# Instruction block: 10110xxx
# Count: 8 instructions
class Instruction_OR_R8(ArithmethicInstruction):
    bin_format = '10110sss'
    name = 'OR A,r8'

    def compute_result(self, a, reg):
        log.warn('Instruction %s flag semantics not implemented' % self.name)
        return a | reg

# Instruction block: 10111xxx
# Count: 8 instructions
class Instruction_CP_R8(ArithmethicInstruction):
    bin_format = '10111sss'
    name = 'CP'

    def compute_result(self, a, reg):
        log.warn('Instruction %s flag semantics not implemented' % self.name)
        return a == reg
    
    def commit_result(self, res):
        return None
