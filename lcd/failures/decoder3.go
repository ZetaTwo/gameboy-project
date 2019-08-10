package main

import (
    "fmt"
    "log"

    "periph.io/x/periph/conn/gpio"
    "periph.io/x/periph/conn/gpio/gpioreg"
    "periph.io/x/periph/host"
)

func main() {
    // Load all the drivers:
    if _, err := host.Init(); err != nil {
        log.Fatal(err)
    }

	/*
	PIN_HSYNC = 2
	PIN_D0 = 3
	PIN_D1 = 6
	PIN_CLK = 5
	PIN_VSYNC = 7
	*/

    // Initialize pins
    pin_hsync := gpioreg.ByName("GPIO2")
    if pin_hsync == nil {
        log.Fatal("Failed to find GPIO2")
	}
	if err := pin_hsync.In(gpio.PullDown, gpio.FallingEdge); err != nil {
        log.Fatal(err)
    }
	
	pin_d0 := gpioreg.ByName("GPIO3")
    if pin_d0 == nil {
        log.Fatal("Failed to find GPIO3")
	}
	if err := pin_d0.In(gpio.PullDown, gpio.NoEdge); err != nil {
        log.Fatal(err)
    }

	
	pin_d1 := gpioreg.ByName("GPIO6")
    if pin_d1 == nil {
        log.Fatal("Failed to find GPIO6")
	}
	if err := pin_d1.In(gpio.PullDown, gpio.NoEdge); err != nil {
        log.Fatal(err)
    }

	
	pin_clk := gpioreg.ByName("GPIO5")
    if pin_clk == nil {
        log.Fatal("Failed to find GPIO5")
	}
	if err := pin_clk.In(gpio.PullDown, gpio.FallingEdge); err != nil {
        log.Fatal(err)
    }
	
	pin_vsync := gpioreg.ByName("GPIO7")
    if pin_vsync == nil {
        log.Fatal("Failed to find GPIO7")
	}
	if err := pin_vsync.In(gpio.PullDown, gpio.FallingEdge); err != nil {
        log.Fatal(err)
    }

    
    fmt.Printf("Starting\n")
   
    // Wait for edges as detected by the hardware, and print the value read:
    for {
	   
		pin_vsync.WaitForEdge(-1)
		fmt.Printf("A\n")
		x := 0
		y := 0
		for {
			for {
				pin_clk.WaitForEdge(-1)
				x++
				//fmt.Printf("x: %d\n", x)
				if x == 160 {
					break
				}
			}
			y++
			//fmt.Printf("y: %d\n", y)
			x = 0
			if y == 144 {
				break
			}
			pin_hsync.WaitForEdge(-1)
		}

		fmt.Printf("x: %d, y: %d\n", x, y)
    }
}
