`default_nettype none

module gameboy_lcd_decoder #(
  parameter DATA_WIDTH=2,
  parameter ADDR_WIDTH=15
)(
  input wire clock,
  input wire reset,

  input wire pixel_clock,
  input wire h_sync,
  input wire v_sync,
  input wire lcd_data0,
  input wire lcd_data1,

  output wire buffer_select,
  output wire [DATA_WIDTH-1:0] pixel_data,
  output wire [ADDR_WIDTH-1:0] pixel_addr,
);

  assign buffer_select = 0;
  assign pixel_data = 2'b0;
  assign pixel_addr = 15'b0;

endmodule
