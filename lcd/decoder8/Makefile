# Based on https://github.com/icebreaker-fpga/icebreaker-examples/blob/master/main.mk

PROJ = gameboy_capture_card
PIN_DEF = icebreaker.pcf
DEVICE = up5k
ADD_SRC = gameboy_frame_buffer.v gameboy_lcd_decoder.v hdmi_output.v

all: $(PROJ).rpt $(PROJ).bin

%.blif: %.v $(ADD_SRC) $(ADD_DEPS)
	yosys -ql $*.log $(if $(USE_ARACHNEPNR),-DUSE_ARACHNEPNR) -p 'synth_ice40 -top $(PROJ) -blif $@' $< $(ADD_SRC)

%.json: %.v $(ADD_SRC) $(ADD_DEPS)
	yosys -ql $*.log $(if $(USE_ARACHNEPNR),-DUSE_ARACHNEPNR) -p 'synth_ice40 -top $(PROJ) -json $@' $< $(ADD_SRC)

ifeq ($(USE_ARACHNEPNR),)
%.asc: $(PIN_DEF) %.json
	nextpnr-ice40 --$(DEVICE) $(if $(PACKAGE),--package $(PACKAGE)) $(if $(FREQ),--freq $(FREQ)) --json $(filter-out $<,$^) --pcf $< --asc $@
else
%.asc: $(PIN_DEF) %.blif
	arachne-pnr -d $(subst up,,$(subst hx,,$(subst lp,,$(DEVICE)))) $(if $(PACKAGE),-P $(PACKAGE)) -o $@ -p $^
endif


%.bin: %.asc
	icepack $< $@

%.rpt: %.asc
	icetime $(if $(FREQ),-c $(FREQ)) -d $(DEVICE) -mtr $@ $<

%_tb: %_tb.v %.v
	iverilog -g2012 -o $@ $^

%_tb.vcd: %_tb
	vvp -N $< +vcd=$@

%_syn.v: %.blif
	yosys -p 'read_blif -wideports $^; write_verilog $@'

%_syntb: %_tb.v %_syn.v
	iverilog -o $@ $^ `yosys-config --datdir/ice40/cells_sim.v`

%_syntb.vcd: %_syntb
	vvp -N $< +vcd=$@

build: $(PROJ).bin

prog: $(PROJ).bin
	iceprog $<

sudo-prog: $(PROJ).bin
	@echo 'Executing prog as root!!!'
	sudo iceprog $<

obj_dir/V%.mk: %.v
	verilator -Wall -Wpedantic -cc $<

obj_dir/V%__ALL.a: obj_dir/V%.mk
	cd obj_dir && make -f ../$<

$(PROJ): obj_dir/V$(PROJ)__ALL.a
	g++ -I /usr/share/verilator/include -I obj_dir /usr/share/verilator/include/verilated.cpp $(PROJ).cpp obj_dir/V$(PROJ)__ALL.a -o $(PROJ)

sim: $(PROJ)
	./$<

clean:
	rm -f $(PROJ).blif $(PROJ).asc $(PROJ).rpt $(PROJ).bin $(PROJ).json $(PROJ).log $(PROJ) $(ADD_CLEAN)
	rm -rf obj_dir

.SECONDARY:
.PHONY: all prog clean sim

