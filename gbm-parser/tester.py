#!/usr/bin/env python3

from kaitaistruct import KaitaiStream
from kaitai_parser.gbr1 import Gbr1


body_parsers = {
    
}

def dump_gbr_file(file):
    print(gbr1.magic)
    for gbr_object in gbr1.objects:
        print('Type: %04X, ID: %d' % (gbr_object.object_type, gbr_object.object_id))
        print('Size: %d' % gbr_object.object_length)
        #body_parsers[gbr_object.object_type](gbr_object.body)
        print('')

if __name__ == '__main__':
    files = ['buttons_unpressed.gbm']
    for filename in files:
        with open('test/%s' % filename, 'rb') as fin:
            gbr1 = Gbr1(KaitaiStream(fin))
            dump_gbr_file(gbr1)
        print('---'*10)
