`default_nettype none

module hdmi_output #(
  parameter DATA_WIDTH=2,
  parameter ADDR_WIDTH=15
)(
  input wire clock,
  input wire reset,

  output    [ADDR_WIDTH-1:0] data_addr,
  input     [DATA_WIDTH-1:0] pixel_data
);

    assign data_addr = 15'b0;

endmodule
