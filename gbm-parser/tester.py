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
    0x0001: parse_object_producer,
    0x0002: parse_object_map,
    0x0003: parse_object_map_tile_data,
    0x0004: parse_object_map_properties,
    0x0005: parse_object_map_property_data,
    0x0006: parse_object_map_default_property_value,
    0x0007: parse_object_map_settings,
    0x0008: parse_object_map_property_colors,
    0x0009: parse_object_map_export_settings,
    0x000A: parse_object_map_export_properties,
    0xFFFF: parse_object_deleted,
}

def dump_gbr_file(file):
    print(gbr1.magic)
    for gbr_object in gbr1.objects:
        print('Type: %04X, ID: %d' % (gbr_object.object_type, gbr_object.object_id))
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
