import angr
import gameboy

p = angr.Project('../roms/gb-calc.gb')
state = p.factory.entry_state()
sm = p.factory.simgr(state)
sm.step(until=lambda lpg: len(lpg.active) > 1)
input_0 = sm.active[0].posix.dumps(0)
