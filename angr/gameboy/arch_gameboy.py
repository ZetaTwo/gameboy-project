from archinfo.arch import Arch, Register, Endness
from archinfo.arch import register_arch

class ArchGameboy(Arch):
    bits = 24
    name = "Gameboy"
    vex_arch = None
    instruction_alignment = 1

    memory_endness = Endness.LE
    register_list = [
        Register(name='af', size=16,  vex_offset=0 ),
        Register(name='a',  size=8,   vex_offset=0 ),
        Register(name='f',  size=8,   vex_offset=8 ),
        Register(name='bc', size=16,  vex_offset=16),
        Register(name='b',  size=8,   vex_offset=16),
        Register(name='c',  size=8,   vex_offset=24),
        Register(name='de', size=16,  vex_offset=32),
        Register(name='d',  size=8,   vex_offset=32),
        Register(name='e',  size=8,   vex_offset=40),
        Register(name='hl', size=16,  vex_offset=48),
        Register(name='h',  size=8,   vex_offset=48),
        Register(name='l',  size=8,   vex_offset=56),
        Register(name='sp', size=16,  vex_offset=64),
        Register(name='pc', size=16,  vex_offset=80),
        Register(name='ip', size=16,  vex_offset=80), # Alias
    ]

    ip_offset = 10
    sp_offset = 8
    # bp_offset = 128 # Not used?
    default_register_values = [
        ('pc', 0x100, False, None)
    ]

    def __init__(self, endness=Endness.LE):
        super().__init__(endness)

register_arch([r'gameboy'], 8, 'Iend_BE', ArchGameboy)
