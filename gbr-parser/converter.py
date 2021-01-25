#!/usr/bin/env python3

from kaitaistruct import KaitaiStream
from kaitai_parser.gbr0 import Gbr0

import struct
import os
from PIL import Image


def ensure_dir(path):
    try:
        os.makedirs(path)
    except FileExistsError:
        pass


def parse_tiles(gbr0):
    # Find all tile data objects
    tiles = {gbr_object.object_id: {
        'data': gbr_object.body,
        'settings': None,
        'import': None,
        'export': None,
        'palettes': None,
        'palette_maps': None,
    } for gbr_object in gbr0.objects if gbr_object.object_type == Gbr0.Gbr0Object.Type.tile_data}

    for gbr_object in gbr0.objects:
        if gbr_object.object_type == Gbr0.Gbr0Object.Type.tile_settings:
            if tiles[gbr_object.body.tile_id]['settings']:
                raise ValueError(
                    'settings is already set for tile ID %d' % gbr_object.body.tile_id)
            tiles[gbr_object.body.tile_id]['settings'] = gbr_object.body
        elif gbr_object.object_type == Gbr0.Gbr0Object.Type.tile_export:
            if tiles[gbr_object.body.tile_id]['export']:
                raise ValueError(
                    'export is already set for tile ID %d' % gbr_object.body.tile_id)
            tiles[gbr_object.body.tile_id]['export'] = gbr_object.body
        elif gbr_object.object_type == Gbr0.Gbr0Object.Type.tile_import:
            if tiles[gbr_object.body.tile_id]['import']:
                raise ValueError(
                    'import is already set for tile ID %d' % gbr_object.body.tile_id)
            tiles[gbr_object.body.tile_id]['import'] = gbr_object.body
        elif gbr_object.object_type == Gbr0.Gbr0Object.Type.palettes:
            if tiles[gbr_object.body.id]['palettes']:
                raise ValueError(
                    'palettes is already set for tile ID %d' % gbr_object.body.id)
            tiles[gbr_object.body.id]['palettes'] = gbr_object.body
        elif gbr_object.object_type == Gbr0.Gbr0Object.Type.tile_pal:
            if tiles[gbr_object.body.id]['palette_maps']:
                raise ValueError(
                    'palette_maps is already set for tile ID %d' % gbr_object.body.id)
            tiles[gbr_object.body.id]['palette_maps'] = gbr_object.body
    return tiles.values()


def convert_color(color_number):
    col_bytes = struct.pack('<I', color_number)
    color = list(struct.unpack('<BBBB', col_bytes))
    color[-1] = 255-color[-1]
    return tuple(color)


def convert_images(tiles):
    res = []
    for tile in tiles:
        res.append([])
        for i in range(tile['data'].count):
            palette_index = tile['palette_maps'].color_set[i]
            palette = tile['palettes'].colors[palette_index]
            im = Image.new('RGBA', (tile['data'].width, tile['data'].height))
            for y in range(tile['data'].height):
                for x in range(tile['data'].width):
                    color = convert_color(
                        palette.colors[tile['data'].tiles[i][y*tile['data'].width+x]])
                    im.putpixel((x, y), color)
            res[-1].append(im)
    return res


def export_images(basepath, images):
    for i in range(len(images)):
        set_path = os.path.join(basepath, str(i))
        ensure_dir(set_path)
        for j in range(len(images[i])):
            image_path = os.path.join(set_path, str('%d.png' % j))
            images[i][j].save(image_path)


if __name__ == '__main__':
    files = ['8x8.gbr', 'alpha.gbr', 'digits.gbr',
             'shaded_alpha.gbr', 'shadow.gbr']
    for filename in files:
        with open(os.path.join('test', filename), 'rb') as fin:
            gbr0 = Gbr0(KaitaiStream(fin))
            tiles = parse_tiles(gbr0)
            images = convert_images(tiles)
            export_images(os.path.join('export', filename), images)
