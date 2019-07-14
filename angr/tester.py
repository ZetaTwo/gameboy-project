import logging
#logging.basicConfig(level=logging.DEBUG)

import angr
from gameboy import arch_gameboy, load_gameboy, simos_gameboy, lift_gameboy

proj = angr.Project('../roms/gb-calc.gb', load_options={'rebase_granularity': 8})


addrs = [0x100, 0x150, 0x161, 0x164, 0x16d, 0x176, 0x4853, 0x485d]


for addr in addrs:
    block4 = proj.factory.block(addr)
    block4.vex.pp()


"""
print(block1.next)
print(dir(block1.next))
block2 = proj.factory.block(block1.next).vex
block2.pp()
"""

#cfg = proj.analyses.CFGFast()


#state = p.factory.entry_state()
#sm = p.factory.simgr(state)
#sm.run(until=lambda lpg: len(lpg.active) > 1)
#input_0 = sm.active[0].posix.dumps(0)
