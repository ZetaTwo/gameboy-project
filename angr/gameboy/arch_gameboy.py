from archinfo.arch import register_arch, Arch


class ArchGameboy(Arch):
    def __init__(self, endness="Iend_LE"):
        super().__init__(endness)
        # TODO: Wat?
        # TODO: Define function prologs
        self.ip_offset = 0
        self.sp_offset = 2
        # bp_offset = 128
        # ret_offset = 16
        # lr_offset = 132
        # syscall_num_offset = 16
        self.call_pushes_ret = True
        self.stack_change = -2
        self.branch_delay_slot = False
        self.default_register_values = [
            (n, 0, False, None) for n in self.register_index]
    sizeof = {'short': 16, 'int': 16, 'long': 32, 'long long': 64}
    function_prologs = {}
    function_epilogs = {}
    qemu_name = 'gameboy'

    bits = 8
    name = "Gameboy"
    # Yep.  MSP's instructions are endy-flipped when stored relative to the ISA.
    instruction_endness = "Iend_LE"
    ida_processor = 'gameboy'
    max_inst_bytes = 3
    ret_instruction = "\xC9"
    nop_instruction = "\x00"
    instruction_alignment = 1
    persistent_regs = []

    entry_register_values = {
    }

    default_symbolic_registers = []

    #TODO: Wat?
    class Mode:
        REGISTER_MODE = 0
        INDEXED_MODE = 1
        INDIRECT_REGISTER_MODE = 2
        INDIRECT_AUTOINCREMENT_MODE = 3
        SYMBOLIC_MODE = 4
        ABSOLUTE_MODE = 5
        IMMEDIATE_MODE = 6
        CONSTANT_MODE0 = 7
        CONSTANT_MODE1 = 8
        CONSTANT_MODE2 = 9
        CONSTANT_MODE4 = 10
        CONSTANT_MODE8 = 11
        CONSTANT_MODE_NEG1 = 12
        OFFSET = 13

    register_index = [
        'a',
        'b',
        'c',
        'd',
        'e',
        'f',
        'h',
        'l',
        'sp',
        'pc',
    ]
    register_names = {
        0: 'a',
        1: 'b',
        2: 'c',
        3: 'd',
        4: 'e',
        5: 'f',
        6: 'h',
        7: 'l',
        8: 'sp',
        9: 'pc',
    }

    registers = {
        'a': (0, 2),
        'b': (0, 2),
        'c': (0, 2),
        'd': (2, 2),
        'e': (2, 2),
        'f': (4, 2),
        'h': (4, 2),
        'l': (6, 2),
        'sp': (6, 2),
        'pc': (6, 2),
    }
    argument_registers = {
        registers['r4'][0],
        registers['r5'][0],
        registers['r6'][0],
        registers['r7'][0],
        registers['r8'][0],
        registers['r9'][0],
        registers['r10'][0],
        registers['r11'][0],
        registers['r12'][0],
        registers['r13'][0],
        registers['r14'][0],
        registers['r15'][0],
    }

    # TODO: Wat?
    # EDG: Can you even use PIC here? I don't think so
    dynamic_tag_translation = {}


register_arch([r'gameboy'], 8, 'Iend_LE', ArchGameboy)
