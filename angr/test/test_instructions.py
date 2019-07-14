import logging
log = logging.getLogger(__name__)

from nose.tools import assert_equal
import gameboy.instrs_gameboy as instrs_gameboy
from itertools import chain

import re

def test_number_instructions():
    # Parse format patterns
    patterns = []
    trailers = ['a'*16, 'd'*16, 'a'*8, 'd'*8]
    instrs = [instrs_gameboy.__dict__[x] for x in filter(lambda x: x.startswith("Instruction_"), instrs_gameboy.__dict__.keys())]
    for instr in instrs:
        bin_format = instr.bin_format
        for trailer in trailers:
            if bin_format.endswith(trailer):
                bin_format = bin_format[:-len(trailer)]

        bin_format = re.sub(r'[^10]', '[10]', bin_format.zfill(16))
        patterns.append(bin_format)
    
    # Count instruction converage
    total_instructions = 0
    for i in chain(range(0x100), range((0xCB<<8), (0xCB<<8) + 0x100)):
        bitstring = format(i, '016b')
        for pattern in patterns:
            if re.match(pattern, bitstring):
                total_instructions += 1
                break
        else:
            log.debug('Not found: %02x', i)

    # Make sure we have covered all instructions
    assert_equal(total_instructions, 256 + 64 + 64 + 64 + (16-1)+3+7+1+2+3+6+2+4+7+2)
