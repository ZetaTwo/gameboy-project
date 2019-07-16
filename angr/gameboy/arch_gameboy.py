import logging
log = logging.getLogger(__name__)

from archinfo.arch import Arch, Register, Endness
from archinfo.arch import register_arch

class ArchGameboy(Arch):
    bits = 24
    name = "Gameboy"
    vex_arch = None
    instruction_alignment = 1

    memory_endness = Endness.LE
    register_list = [
        Register(name='af', size=2,  vex_offset=0 ),
        Register(name='a',  size=1,   vex_offset=0 ),
        Register(name='f',  size=1,   vex_offset=8 ),
        Register(name='bc', size=2,  vex_offset=16),
        Register(name='b',  size=1,   vex_offset=16),
        Register(name='c',  size=1,   vex_offset=24),
        Register(name='de', size=2,  vex_offset=32),
        Register(name='d',  size=1,   vex_offset=32),
        Register(name='e',  size=1,   vex_offset=40),
        Register(name='hl', size=2,  vex_offset=48),
        Register(name='h',  size=1,   vex_offset=48),
        Register(name='l',  size=1,   vex_offset=56),
        Register(name='sp', size=2,  vex_offset=64),
        Register(name='pc', size=2,  vex_offset=80),
        Register(name='ip', size=2,  vex_offset=80), # Alias
    ]

    ip_offset = 10
    sp_offset = 8
    call_pushes_ret = True
    stack_change = -2
    # bp_offset = 128 # Not used?
    default_register_values = [
        ('pc', 0x100, False, None),
        ('sp', 0xFFFF, False, None)
    ]
    sizeof = {'short': 16, 'int': 16, 'long': 32, 'long long': 64}

    flags = {
        'ZERO': 7,
        'NEGATIVE': 6,
        'HALF_CARRY': 5,
        'CARRY': 4
    }

    def __init__(self, endness=Endness.LE):
        super().__init__(endness)

register_arch([r'gameboy'], 8, 'Iend_BE', ArchGameboy)
