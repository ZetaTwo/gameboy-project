# Gameboy Project

This repository contains tools and files for hacking on the Game Boy.
The idea is to create a framework to for scripted analysis including emulation to allow for fuzzing and symbolic execution of Game Boy ROMs.

## Roadmap

Current roadmap of the project

* Symbolic execution
  - Model all instructions (PyVex lifting)
  - Model memory mapped registers (Custom memory plugin in angr)
  - Model banking (segmment register, virtual 8+16=24 bit space)
  - Model periodic interrupts (vlank, hblank)
* HDMI adapter
  - Real time capture (FPGA+Verilog)
  - Real time rendering (SDL)
  - Sound (USB sound card + 3,5mm cable)
* Emulation
  - Cycle perfect emulation
  - Execution traces
  - Scriptable debugger
  - "overclockable" (allow to run headless at arbitrary speed)

## Docs

We have gathered some documentation in the [docs](/docs/docs.md).

## Authors

- [Calle "Zeta Two" Svensson](https://github.com/ZetaTwo)
- [b0bb](https://github.com/0xb0bb)
