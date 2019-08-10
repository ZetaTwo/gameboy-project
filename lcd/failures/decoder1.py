#!/usr/bin/env python3

# NOT FAST ENOUGH

from gpiozero import DigitalInputDevice
from signal import pause
import sys

#from PIL import Image

hsync = DigitalInputDevice(3, pull_up=True)
d0 = DigitalInputDevice(4)
d1 = DigitalInputDevice(5)
clk = DigitalInputDevice(6)
vsync = DigitalInputDevice(7)

state = {
    'x': 0,
    'y': 0,
    'frame': 0,
}

def start_frame():
    state['x'] = 0
    state['y'] = 0
    state['frame'] += 1
    print('frame')

def start_line():
    state['y'] += 1
    state['x'] = 0
    print('line')

def clock_pixel():
    print(d0.is_active, d1.is_active, clk.is_active)
    #sys.exit(1)

vsync.when_deactivated = start_frame
hsync.when_deactivated = start_line
clk.when_deactivated = clock_pixel

try:
    pause()
except:
    print(state)
