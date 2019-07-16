import logging
#logging.basicConfig(level=logging.DEBUG)

import angr
from gameboy import arch_gameboy, load_gameboy, simos_gameboy, lift_gameboy

proj = angr.Project('../roms/gb-calc.gb', load_options={'rebase_granularity': 8})


addrs = [0x100, 0x150, 0x161, 0x164, 0x16d, 0x176, 0x4853, 0x485d]


#block1 = proj.factory.block(proj.entry)


"""
for addr in addrs:
    block4 = proj.factory.block(addr)
    block4.vex.pp()
"""

"""
print(block1.next)
print(dir(block1.next))
block2 = proj.factory.block(block1.next).vex
block2.pp()
"""

#cfg = proj.analyses.CFGFast()

#block1 = proj.factory.block(proj.entry)
#block1.vex.pp()

state = proj.factory.entry_state()
sm = proj.factory.simgr(state)
#sm.step()
#sm.explore(find=0x150)
sm.explore(find=0x151)

found = sm.found[0]
print(found.regs.c)
print(found.regs.a)
print(found.regs.b)
print(found.regs.sp)
print(found.regs.hl)