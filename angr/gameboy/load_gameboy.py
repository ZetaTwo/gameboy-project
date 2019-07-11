from cle.backends import Blob, register_backend
from archinfo import arch_from_id

import re
import logging
import struct

from .engine_gameboy import gameboy_engine_preset

log = logging.getLogger(__name__)

__all__ = ('GameboyROM',)

class GameboyROM(Blob):
    """
    Representation of a Gameboy ROM.
    """
    is_default = True

    def __init__(self, path, offset=0, ignore_checksum=False, *args, **kwargs):
        """
        Loader backend for Gameboy ROMs
        :param path: The file path
        :param offset: Skip this many bytes from the beginning of the file.
        """
        super(GameboyROM, self).__init__(path, *args,
                arch=arch_from_id("gameboy"),
                offset=offset,
                entry_point=0x100,
                **kwargs)
        self.os = "gameboy"
        #self.engine_preset = gameboy_engine_preset
        self.ignore_checksum = ignore_checksum #TODO: Doesn't do anything

    @staticmethod
    def _validate_header_checksum(gb_header):
        hdr_header_checksum = gb_header[0x4D]

        calculated_header_checksum = 0
        for i in range(0x34, 0x4D):
            calculated_header_checksum = (calculated_header_checksum - gb_header[i] - 1) & 0xFF
        
        if hdr_header_checksum != calculated_header_checksum:
            log.debug('Gameboy header checksum does not match: %02x != %02x', calculated_header_checksum, hdr_header_checksum)

        return hdr_header_checksum == calculated_header_checksum

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        gb_rom_data = stream.read()

        # Parse header
        if len(gb_rom_data) < 0x150:
            log.debug('Not enough data for Gameboy header')
            return False

        log.debug('Parsing Gameboy header')
        gb_header = gb_rom_data[0x100:0x150]

        """
        # TODO: Use this for something?
        hdr_entry = gb_header[0x0:0x4]
        hdr_nintendo_logo = gb_header[0x4:0x34]
        hdr_title = gb_header[0x34:0x3F]
        hdr_manufacturer_code = gb_header[0x3F:0x43]
        hdr_cgb_flag = gb_header[0x43]
        hdr_new_licensee_code = gb_header[0x44:0x46]
        hdr_sgb_flag = gb_header[0x46]
        hdr_cartridge_type = gb_header[0x47]
        hdr_rom_size = gb_header[0x48]
        hdr_ram_size = gb_header[0x49]
        hdr_destination_code = gb_header[0x4A]
        hdr_old_licensee_code = gb_header[0x4B]
        hdr_mask_rom_version_number = gb_header[0x4C]
        """
        
        if not GameboyROM._validate_header_checksum(gb_header):
            return False

        # Calculate ROM checksum
        hdr_global_checksum = struct.unpack('>H', gb_header[0x4E:0x50])[0]
        calculated_global_checksum = (sum(gb_rom_data[:0x14E])+sum(gb_rom_data[0x150:])) & 0xFFFF

        if calculated_global_checksum != hdr_global_checksum:
            log.warn('Global checksum does not match: %04x != %04x', calculated_global_checksum, hdr_global_checksum)
            #if not self.ignore_checksum:
            return False

        log.debug('Gameboy header valid')
        return True

"""
# TODO: Needed?
    def _load(self, offset, size=None):
        """"""
        Load a segment into memory.
        """"""
        self.binary_stream.seek(offset)
        if size is None:
            string = self.binary_stream.read()
        else:
            string = self.binary_stream.read(size)
        self.memory.add_backer(0, string)
        self._max_addr = len(string)
"""

register_backend("gameboy", GameboyROM)
