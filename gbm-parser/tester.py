#!/usr/bin/env python3

from kaitaistruct import KaitaiStream
from kaitai_parser.gbr1 import Gbr1

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

def parse_object_map_properties(body):
    print('MapProperties')

def parse_object_map_property_data(body):
    print('MapPropertyData')

def parse_object_map_default_property_value(body):
    print('MapDefaultPropertyValue')

def parse_object_map_settings(body):
    print('MapSettings')

def parse_object_map_property_colors(body):
    print('MapPropertyColors')

def parse_object_map_export_settings(body):
    print('MapExportSettings')

def parse_object_map_export_properties(body):
    print('MapExportProperties')

def parse_object_deleted(body):
    print('Deleted')


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
    Gbr1.Gbr1Object.Type.deleted:                    parse_object_deleted,
}

def dump_gbr_file(file):
    print(gbr1.magic)
    for gbr_object in gbr1.objects:
        print('Type: %s, ID: %d' % (gbr_object.object_type, gbr_object.object_id))
        print('Size: %d' % gbr_object.object_length)
        body_parsers[gbr_object.object_type](gbr_object.body)
        print('')

if __name__ == '__main__':
    files = ['buttons_unpressed.gbm']
    for filename in files:
        with open('test/%s' % filename, 'rb') as fin:
            gbr1 = Gbr1(KaitaiStream(fin))
            dump_gbr_file(gbr1)
        print('---'*10)
