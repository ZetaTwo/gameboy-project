#!/usr/bin/env python3

from kaitaistruct import KaitaiStream
from kaitai_parser.gbr0 import Gbr0

def parse_object_producer(body):
    print('Producer')
    print('\tName: %s' % body.name)
    print('\tVersion: %s' % body.version)
    print('\tInfo: %s' % body.info)

def parse_object_tile_data(body):
    print('TileData')
    print('\tName: %s' % body.name)
    print('\tWidth: %s' % body.width)
    print('\tHeight: %s' % body.height)
    print('\tCount: %s' % body.count)
    print('\tColorSet: %s' % body.color_set)
    print('\tTiles: %s' % len(body.tiles))

def parse_object_tile_settings(body):
    print('TileSettings')
    print('\tTileID: %s' % body.tile_id)
    print('\tSimple: %s' % body.simple)
    print('\tFlags: %s' % body.flags)
    print('\tLeftColor: %s' % body.left_color)
    print('\tRightColor: %s' % body.right_color)
    print('\tSplitWidth: %s' % body.split_width)
    print('\tSplitHeight: %s' % body.split_height)
    print('\tSplitOrder: %s' % body.split_order)
    print('\tColorSet: %s' % body.color_set)
    print('\tBookmarks: %s' % body.bookmarks)
    print('\tAutoUpdate: %s' % body.auto_update)

def parse_object_tile_export(body):
    print('TileExport')
    print('\tTileID: %s' % body.tile_id)
    print('\tFileName: %s' % body.file_name)
    print('\tFileType: %s' % body.file_type)
    print('\tSectionName: %s' % body.section_name)
    print('\tLabelName: %s' % body.label_name)
    print('\tBank: %s' % body.bank)
    print('\tTileArray: %s' % body.tile_array)
    print('\tFormat: %s' % body.format)
    print('\tCounter: %s' % body.counter)
    print('\tExportFrom: %s' % body.export_from)
    print('\tExportTo: %s' % body.export_to)
    print('\tCompression: %s' % body.compression)
    print('\tIncludeColors: %s' % body.include_colors)
    print('\tSGBPalettes: %s' % body.sgb_palettes)
    print('\tGBCPalettes: %s' % body.gbc_palettes)
    print('\tMakeMetaTiles: %s' % body.make_meta_tiles)
    print('\tMetaOffset: %s' % body.meta_offset)
    print('\tMetaCounter: %s' % body.meta_counter)
    print('\tSplit: %s' % body.split)
    print('\tBlockSize: %s' % body.block_size)
    print('\tSelTab: %s' % body.sel_tab)

def parse_object_tile_import(body):
    print('TileImport')
    print('\tTileID: %s' % body.tile_id)
    print('\tFileName: %s' % body.file_name)
    print('\tFileType: %s' % body.file_type)
    print('\tFromTile: %s' % body.from_tile)
    print('\tToTile: %s' % body.to_tile)
    print('\tTileCount: %s' % body.tile_count)
    print('\tColorConversion: %s' % body.color_conversion)
    print('\tFirstByte: %s' % body.first_byte)
    print('\tBinaryFileType: %s' % body.binary_file_type)

def parse_object_palette(palette):
    return '(%08x, %08x, %08x, %08x)' % tuple(palette.colors)

def parse_object_palettes(body):
    print('Palettes')
    print('\tID: %s' % body.id)
    print('\tCount: %s' % body.count)
    print('\tColors:\n\t\t%s' % ',\n\t\t'.join([parse_object_palette(palette) for palette in body.colors]))
    print('\tSGBCount: %s' % body.sgb_count)
    print('\tSGBColors:\n\t\t%s' % ',\n\t\t'.join([parse_object_palette(palette) for palette in body.sgb_colors]))

def parse_object_tile_pal(body):
    print('TilePal')
    print('\tID: %s' % body.id)
    print('\tCount: %s' % body.count)
    print('\tColorSet: %s' % body.color_set)
    print('\tSGBCount: %s' % body.sgb_count)
    print('\tSGBColorSet: %s' % body.sgb_color_set)

def parse_object_deleted(body):
    print('Deleted')


body_parsers = {
    Gbr0.Gbr0Object.Type.producer:      parse_object_producer,
    Gbr0.Gbr0Object.Type.tile_data:     parse_object_tile_data,
    Gbr0.Gbr0Object.Type.tile_settings: parse_object_tile_settings,
    Gbr0.Gbr0Object.Type.tile_export:   parse_object_tile_export,
    Gbr0.Gbr0Object.Type.tile_import:   parse_object_tile_import,
    Gbr0.Gbr0Object.Type.palettes:      parse_object_palettes,
    Gbr0.Gbr0Object.Type.tile_pal:      parse_object_tile_pal,
    Gbr0.Gbr0Object.Type.deleted:       parse_object_deleted,
}

def dump_gbr_file(file):
    print(gbr0.magic)
    for gbr_object in gbr0.objects:
        print('Type: %s, ID: %d' % (gbr_object.object_type, gbr_object.object_id))
        print('Size: %d' % gbr_object.record_length)
        body_parsers[gbr_object.object_type](gbr_object.body)
        print('')

if __name__ == '__main__':
    files = ['8x8.gbr', 'alpha.gbr', 'digits.gbr', 'shaded_alpha.gbr', 'shadow.gbr']
    for filename in files:
        with open('test/%s' % filename, 'rb') as fin:
            gbr0 = Gbr0(KaitaiStream(fin))
            dump_gbr_file(gbr0)
        print('---'*10)
