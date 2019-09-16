#!/usr/bin/env python3

from PIL import Image
import sys

IMAGE_WIDTH = 160
IMAGE_HEIGHT = 144
TILE_WIDTH = 8
TILE_HEIGHT = 8

def tilemap_c(tilemap, name):
    print('const UINT8 %s[] = {' % name)
    assert(len(tilemap) == 18)
    for row in tilemap:
        assert(len(row) == 20)
        print('\t'+', '.join(['%#04x' % x for x in row])+',')
    print('};')

def tiledata_c(encoded_tiles, name):
    print('const UINT8 %s_data_len = %d;' % (name, len(encoded_tiles)))
    print('const UINT8 %s_data[] = {' % name)
    for tile in encoded_tiles:
        assert(len(tile) == 8+8)
        print('\t'+', '.join(['%#04x' % x for x in tile[:8]])+',')
        print('\t'+', '.join(['%#04x' % x for x in tile[8:]])+',')
    print('};')

def encode_tiles(tiles):
    """Convert a list of tiles to Game Boy format"""
    encoded_tiles = []
    for tile in tiles:
        tile_low, tile_high = [], []
        for y in range(TILE_HEIGHT):
            row_low, row_high = 0, 0
            for x in range(TILE_WIDTH):
                color_index = tile[y*TILE_HEIGHT+x]
                row_low = (row_low << 1)   | ((color_index>>0) & 1)
                row_high = (row_high << 1) | ((color_index>>1) & 1)
            tile_low.append(row_low)
            tile_high.append(row_high)
        encoded_tile = [z for pair in zip(tile_low,tile_high) for z in pair]
        assert(len(encoded_tile) == 8+8)
        encoded_tiles.append(encoded_tile)
    return encoded_tiles

def round_up_tile(x):
    """Round number up to nearest multiple of 8"""
    return (x + 7) & (-8)

def create_tiles(colormap):
    """Group color indices into tiles and create index"""
    width, height = len(colormap[0]), len(colormap)
    x_tiles, y_tiles = round_up_tile(width)>>3, round_up_tile(height)>>3
    tiles = {}
    #print(len(colormap), len(colormap[0]))

    tilemap = []
    for by in range(y_tiles):
        maprow = []
        for bx in range(x_tiles):
            tile = []
            for y in range(TILE_HEIGHT):
                for x in range(TILE_WIDTH):
                    px = colormap[TILE_HEIGHT*by+y][TILE_WIDTH*bx+x]
                    tile.append(px)
            tile=tuple(tile)
            assert(len(tile)==TILE_HEIGHT*TILE_WIDTH)
            if tile not in tiles:
                tiles[tile] = len(tiles)
            maprow.append(tiles[tile])
        tilemap.append(maprow)
    
    tiles = {v:k for k,v in tiles.items()}
    tiles = [tiles[k] for k in sorted(tiles.keys())]
    print('// Number of unique tiles: %d' % len(tiles))
    return len(tiles) <= 256, tiles, tilemap

def luminance(color):
    R, G, B, _ = color
    return 0.2126*R + 0.7152*G + 0.0722*B

def index_colors(pixels):
    """Convert pixel values to indices and index image"""
    colors = {}
    #colorflip = [0, 3, 2, 1] # Front
    #colorflip = [0, 3, 2, 1] # Crash
    #colorflip = [3, 2, 1, 0] # Flag
    colorflip = [0, 2, 1, 3]
    #colorflip = [0, 1, 2, 3]
    colormap = []
    for row in pixels:
        index_row = []
        for px in row:
            if px not in colors:
                colors[px] = colorflip[len(colors)]
            index_row.append(colors[px])
        colormap.append(index_row)
    
    colors = {v:k for k,v in colors.items()}
    colors = [colors[k] for k in sorted(colors.keys())]

    print('// Number of unique colors: %d' % len(colors))
    return len(colors) <= 4, colors, colormap

def get_image_size(im):
    """Get and validate image size"""
    width, height = im.size
    print('// Width: %d, height: %d' % (width, height))
    return width > 0 and width <= IMAGE_WIDTH and height > 0 and height <= IMAGE_HEIGHT, width, height

def extract_pixels(im):
    """Get the pixel data as a 2D array"""
    width, height = im.size
    pixels = list(im.getdata())
    pixels = [pixels[y*width:(y+1)*width] for y in range(height)]
    assert(len(pixels)==height)
    assert(len(pixels[0])==width)
    return pixels


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage: %s <image> <name>' % sys.argv[0])
        sys.exit(1)

    im = Image.open(sys.argv[1])
    ok, *_ = get_image_size(im)
    if not ok:
        print('Image must use at most 160x144 pixels')
        sys.exit(1)
    
    pixels = extract_pixels(im)
    im.close()
    ok, colors, colormap = index_colors(pixels)
    
    if not ok:
        print('Image must use at most 4 colors')
        sys.exit(1)

    ok, tiles, tilemap = create_tiles(colormap)

    if not ok:
        print('Image must have at most 256 unique 8x8 pixel blocks')
        sys.exit(1)

    encoded_tiles = encode_tiles(tiles)

    print('#include <gb/gb.h>')
    print('#include "midnightlogo.h"')
    tiledata_c(encoded_tiles, sys.argv[2])
    tilemap_c(tilemap, sys.argv[2])
