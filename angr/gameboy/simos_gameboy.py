from angr.simos import SimOS, register_simos
from angr.sim_procedure import SimProcedure
from angr.engines.vex import SimEngineVEX
from angr.calling_conventions import SimStackArg, SimRegArg, SimCC, register_syscall_cc, register_default_cc, SimCC
from .arch_gameboy import ArchGameboy

# http://mspgcc.sourceforge.net/manual/x1248.html
class SimCCGameboy(SimCC):
    #ARG_REGS = [ 'r15', 'r14', 'r13', 'r12' ]
    #FP_ARG_REGS = []    # TODO: ???
    #STACKARG_SP_DIFF = 2
    #RETURN_ADDR = SimStackArg(0, 2)
    #RETURN_VAL = SimRegArg('r15', 2)
    ARCH = ArchGameboy

class MCstopexec(SimProcedure):
    pass
    #NO_RET = True
    #def run(self):
    #    self.exit(0)

class MCputs(SimProcedure):
    pass
    #def run(self):
    #    return 1

class MCgetsn(SimProcedure):
    pass
    """
    Microcorruption's getsn:
    Args: R15 has an address to write to.
          R14 has the max number of bytes to read
    """
    #num_args = 2
    #NUM_ARGS = 2
    # pylint:disable=arguments-differ

    #def run(self, ptr, maxbytes):
    #    self.state.posix.fd[0].read(ptr, maxbytes)
    #    # NOTE: The behavior of EOF (this is zero) is undefined!!!
    #    return self.state.solver.Unconstrained('getsn', self.state.arch.bits)


class SimGameboy(SimOS):
    # Syscalls are for lamers
    SYSCALL_TABLE = {}


    def __init__(self, *args, **kwargs):
        super(SimGameboy, self).__init__(*args, name="Gameboy", **kwargs)

    def configure_project(self):
        super(SimGameboy, self).configure_project()

        #self._load_syscalls(SimGameboy.SYSCALL_TABLE, "bf")

    def state_blank(self, data_region_size=0x8000, **kwargs):
        # pylint:disable=arguments-differ
        state = super(SimGameboy, self).state_blank(**kwargs)  # pylint:disable=invalid-name
        # PTR starts halfway through memory
        return state

    def state_entry(self, **kwargs):
        state = super(SimGameboy, self).state_entry(**kwargs)
        return state


class SimGameboySyscall(SimCC):
    ARG_REGS = [ ]
    #RETURN_VAL = ""
    ARCH = ArchGameboy

    @staticmethod
    def _match(arch, args, sp_delta):   # pylint: disable=unused-argument
        # doesn't appear anywhere but syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.inout

register_simos('Standalone App', SimGameboy)
register_syscall_cc('Gameboy', 'default', SimGameboySyscall)
register_default_cc('Gameboy', SimCCGameboy)
