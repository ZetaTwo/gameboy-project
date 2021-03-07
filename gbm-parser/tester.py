#!/usr/bin/env python3

from kaitaistruct import KaitaiStream
from kaitai_parser.gbr1 import Gbr1

MAX_RECORDS = 5

def parse_object_producer(body):
    print('Producer')
    print('\tName: %s' % body.name)
    print('\tVersion: %s' % body.version)
    print('\tInfo: %s' % body.info)

def parse_object_map(body):
    print('Map')
    print('\tName: %s' % body.name)
    print('\tWidth: %s' % body.width)
    print('\tHeight: %s' % body.height)
    print('\tPropCount: %s' % body.prop_count)
    print('\tTileFile: %s' % body.tile_file)
    print('\tTileCount: %s' % body.tile_count)
    print('\tPropColorCount: %s' % body.prop_color_count)

def parse_object_map_tile_data(body):
    print('MapTileData')
    print('\tNum records: %s' % body.num_records)
    for idx, record in enumerate(body.data[:MAX_RECORDS]):
        print('\tMapTileData[%d].tile_number = %d' % (idx, record.tile_number))
    print('\t...')

def parse_object_map_properties(body):
    print('MapProperties')
    print('\tNum records: %s' % body.num_records)
    for idx, record in enumerate(body.data[:MAX_RECORDS]):
        print('\tMapProperties[%d] = %d' % (idx, record.tile_number))
    print('\t...')

def parse_object_map_property_data(body):
    print('MapPropertyData')
    print('\tNum records: %s' % body.num_records)
    for idx, record in enumerate(body.data[:MAX_RECORDS]):
        print('\tMapPropertyData[%d] = %d' % (idx, record.tile_number))
    print('\t...')

def parse_object_map_default_property_value(body):
    print('MapDefaultPropertyValue')
    print('\tNum records: %s' % body.num_records)

def parse_object_map_settings(body):
    print('MapSettings')
    print('\tForm Width: %s' % body.form_width)
    print('\tForm Height: %s' % body.form_height)
    print('\tForm Maximized: %s' % body.form_maximized)
    print('\tInfo Panel: %s' % body.info_panel)
    print('\tGrid: %s' % body.grid)
    print('\tDouble Markers: %s' % body.double_markers)
    print('\tProp Colors: %s' % body.prop_colors)
    print('\tZoom: %s' % body.zoom)
    print('\tColor Set: %s' % body.color_set)
    print('\tBookmarks: %s' % body.bookmarks)
    print('\tBlock Fill Pattern: %s' % body.block_fill_pattern)
    print('\tBlock Fill Width: %s' % body.block_fill_width)
    print('\tBlock Fill Height: %s' % body.block_fill_height)

def parse_object_map_property_colors(body):
    print('MapPropertyColors')
    print('\tNum records: %s' % body.num_records)
    for record in body.data:
        print('\tProperty = %d, Operator = %d, Value = %d' % (record.property, record.operator, record.value))

def parse_object_map_export_settings(body):
    print('MapExportSettings')
    print('\tFile Name: %s' % body.file_name)
    print('\tFile Type: %s' % body.file_type)
    print('\tSection Name: %s' % body.section_name)
    print('\tLabel Name: %s' % body.label_name)
    print('\tBank: %s' % body.bank)
    print('\tPlane Count: %s' % body.plane_count)
    print('\tPlane Order: %s' % body.plane_order)
    print('\tMap Layout: %s' % body.map_layout)
    print('\tSplit: %s' % body.split)
    print('\tSplit Size: %s' % body.split_size)
    print('\tSplit Bank: %s' % body.split_bank)
    print('\tSel Tab: %s' % body.sel_tab)
    print('\tProp Count: %s' % body.prop_count)
    #print('\tTile Offset: %s' % body.tile_offset)

def parse_object_map_export_properties(body):
    print('MapExportProperties')


body_parsers = {
    Gbr1.Gbr1Object.Type.producer:                   parse_object_producer,
    Gbr1.Gbr1Object.Type.map:                        parse_object_map,
    Gbr1.Gbr1Object.Type.map_tile_data:              parse_object_map_tile_data,
    Gbr1.Gbr1Object.Type.map_properties:             parse_object_map_properties,
    Gbr1.Gbr1Object.Type.map_property_data:          parse_object_map_property_data,
    Gbr1.Gbr1Object.Type.map_default_property_value: parse_object_map_default_property_value,
    Gbr1.Gbr1Object.Type.map_settings:               parse_object_map_settings,
    Gbr1.Gbr1Object.Type.map_property_colors:        parse_object_map_property_colors,
    Gbr1.Gbr1Object.Type.map_export_settings:        parse_object_map_export_settings,
    Gbr1.Gbr1Object.Type.map_export_properties:      parse_object_map_export_properties,
}

def dump_gbr_file(file):
    print(gbr1.magic)
    for gbr_object in gbr1.objects:
        print('Type: %s, ID: %d' % (gbr_object.object_type, gbr_object.object_id))
        print('Size: %d' % gbr_object.object_length)
        if gbr_object.object_type in body_parsers:
            body_parsers[gbr_object.object_type](gbr_object.body)
        print('')

if __name__ == '__main__':
    files = ['buttons_unpressed.gbm', 'bg.gbm']
    #files = ['bg.gbm']
    for filename in files:
        with open('test/%s' % filename, 'rb') as fin:
            gbr1 = Gbr1(KaitaiStream(fin))
            dump_gbr_file(gbr1)
        print('---'*10)

