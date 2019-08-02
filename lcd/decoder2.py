#!/usr/bin/env python3

# STILL NOT FAST ENOUGH (We'll have to go _low_)

import pigpio
import time

"""
hsync = DigitalInputDevice(3, pull_up=True)
d0 = DigitalInputDevice(4)
d1 = DigitalInputDevice(5)
clk = DigitalInputDevice(6)
vsync = DigitalInputDevice(7)
"""

PIN_HSYNC = 2
PIN_D0 = 3
PIN_D1 = 6
PIN_CLK = 5
PIN_VSYNC = 7



state = {
    'x': 0,
    'y': 0,
    'frame': 0,
    'd0': 0,
    'd1': 0,
    'buffer': [],
    #'buffers': [],
    #'blen': [],
}

def update_value(gpio, level, tick):
    #print(gpio, level, tick)
    if gpio == PIN_D0:
        state['d0'] = level
    elif gpio == PIN_D1:
        state['d1'] = level

def start_frame(gpio, level, tick):
    print(state['x'], state['y'])
    #state['buffers'].append(state['buffer'])
    #state['blen'].append(len(state['buffer']))
    state['buffer'] = []
    state['x'] = 0
    state['y'] = 0
    state['frame'] += 1
    print(len(state['buffer']))
    #print('frame')

def start_line(gpio, level, tick):
    state['y'] += 1
    state['x'] = 0
    #print('line')

def clock_pixel(gpio, level, tick):
    state['buffer'].append((state['d1'] << 1) | state['d0'])
    #print(state['d0'], state['d1'])
    
pi = pigpio.pi()

pi.set_mode(PIN_HSYNC, pigpio.INPUT)
pi.set_mode(PIN_VSYNC, pigpio.INPUT)
pi.set_mode(PIN_CLK, pigpio.INPUT)
pi.set_mode(PIN_D0, pigpio.INPUT)
pi.set_mode(PIN_D1, pigpio.INPUT)

cbs = [
    pi.callback(PIN_CLK, pigpio.FALLING_EDGE, clock_pixel),
    pi.callback(PIN_HSYNC, pigpio.FALLING_EDGE, start_line),
    pi.callback(PIN_VSYNC, pigpio.FALLING_EDGE, start_frame),
    pi.callback(PIN_D0, pigpio.EITHER_EDGE, update_value),
    pi.callback(PIN_D1, pigpio.EITHER_EDGE, update_value),
]

time.sleep(5)

for cb in cbs:
    cb.cancel()

print(state)


pi.stop()
