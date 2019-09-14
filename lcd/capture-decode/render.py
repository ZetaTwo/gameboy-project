#!/usr/bin/env python3

import sys
import csv
import struct
from PIL import Image

SIZE = (160,144)
COLORS = [tuple([i*85]*3) for i in range(4)][::-1]
COLORS = [struct.unpack('3B', bytes.fromhex(x)) for x in ['dbf4b4', 'abc396', '7b9278', '4c625a']]

im = Image.new('RGB', SIZE)

with open(sys.argv[1], 'r') as fin:
    csvreader = csv.reader(fin)
    next(csvreader, None)

    y = 0
    x = 0
    for line in csvreader:
        im.putpixel((x,y), COLORS[int(line[2])])
        x += 1
        if x == 160:
            y += 1
            x = 0
            if y == 144:
                break

if len(sys.argv) < 3:
    print('Displaying image')
    im.show()
else:
    print('Saving image to "%s"' % sys.argv[2])
    im.save(sys.argv[2])
