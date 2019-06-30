import logging
import warnings

import struct

from miasm.analysis.binary import Container, ContainerSignatureException, ContainerParsingException

log = logging.getLogger(__name__)

## Format dependent classes
class ContainerGameboyROM(Container):
    "Container abstraction for GameBoy ROM"

    def parse(self, data, ignore_checksum=False, **kwargs):
        log.debug('Parsing Gameboy ROM')
        
        # Parse header
        if len(data) < 0x150:
            log.debug('Not enough data for Gameboy header')
            raise ContainerSignatureException()

        log.debug('Parsing Gameboy header')
        gb_header = data[0x100:0x150]
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
        
        hdr_header_checksum = gb_header[0x4D]
        calculated_header_checksum = 0
        for i in range(0x34, 0x4D):
            calculated_header_checksum = (calculated_header_checksum - gb_header[i] - 1) & 0xFF
        if calculated_header_checksum != hdr_header_checksum:
            log.debug('Gameboy header checksum does not match: %02x != %02x', calculated_header_checksum, hdr_header_checksum)
            raise ContainerSignatureException()

        hdr_global_checksum = struct.unpack('>H', gb_header[0x4E:0x50])[0]
        calculated_global_checksum = (sum(data[:0x14E])+sum(data[0x150:])) & 0xFFFF

        if calculated_global_checksum != hdr_global_checksum:
            log.warn('Global checksum does not match: %04x != %04x', calculated_global_checksum, hdr_global_checksum)
            if not ignore_checksum:
                raise ContainerSignatureException()

        self._executable = None
        self._bin_stream = None
        self._entry_point = 0x100
        self._arch = None
        #self._loc_db = None


Container.register_container(ContainerGameboyROM)
