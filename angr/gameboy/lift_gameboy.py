from .arch_gameboy import ArchGameboy
from . import instrs_gameboy as instrs
from pyvex.lifting import register
from pyvex.lifting.util import GymratLifter

class LifterGameboy(GymratLifter):
    # The default behavior of GymratLifter works here.
    # We just grab all the instruction classes out of the other file.
    instrs = [instrs.__dict__[x] for x in filter(lambda x: x.startswith("Instruction_"), instrs.__dict__.keys())]

register(LifterGameboy, 'Gameboy')
