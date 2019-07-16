import logging
log = logging.getLogger(__name__)

from .arch_gameboy import ArchGameboy
from . import instrs_00_gameboy as instrs1
from . import instrs_80_gameboy as instrs2
from . import instrs_cb_gameboy as instrs3
from pyvex.lifting import register
from itertools import chain
from pyvex.lifting.util import GymratLifter

class LifterGameboy(GymratLifter):
    # The default behavior of GymratLifter works here.
    # We just grab all the instruction classes out of the other file.
    
    instr_classes = chain(
        instrs1.__dict__.items(), 
        instrs2.__dict__.items(),
        instrs3.__dict__.items(),
        )
    instrs = [v for k,v in instr_classes if k.startswith('Instruction_')]

register(LifterGameboy, 'Gameboy')
