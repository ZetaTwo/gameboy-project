import angr
import claripy

# NOTE: This will most likely not be needed or used

class SimEngineGameboy(angr.SimEngine):
    def _check(self, state, *args, **kwargs):
        return state.arch.name == 'gameboy'

    def _process(self, state, successors, *args, **kwargs):
        """
        #TODO: implement?
        ins = decode(state, successors.addr)
        ins.execute(state, successors)

        successors.processed = True
        successors.description = str(ins)
        """

# Engine registration
gameboy_engine_preset = angr.engines.basic_preset.copy()
gameboy_engine_preset.add_default_plugin('gameboy', SimEngineGameboy)
gameboy_engine_preset.default_engine = 'gameboy'
gameboy_engine_preset.order = 'gameboy',
