#!/usr/bin/env python3

import logging
logging.basicConfig(level=logging.DEBUG)

from miasm.analysis.machine import Machine
from miasm.analysis import binary

import gameboy

#ROM_PATH = 'test/tetris.gb'
ROM_PATH = 'test/gb-calc.gb'

if __name__ == '__main__':
    with open(ROM_PATH, 'rb') as fin:
        bi = binary.Container.from_stream(fin, ignore_checksum=True)
        print('bin_stream: %s' % bi.bin_stream)
        print('executable: %s' % bi.executable)
        print('entry_point: %s' % bi.entry_point)
        print('arch: %s' % bi.arch)
        print('loc_db: %s' % bi.loc_db)

    #machine = Machine('gameboy')
    #mn, dis_engine_cls, ira_cls = machine.mn, machine.dis_engine, machine.ira