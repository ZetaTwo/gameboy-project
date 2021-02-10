`default_nettype none

module gameboy_frame_buffer #(
  parameter DATA_WIDTH=2,
  parameter ADDR_WIDTH=15
)(
  input wire clock,
  input wire reset,
  input wire buffer_select,
  input      [DATA_WIDTH-1:0] data_in,
  input      [ADDR_WIDTH-1:0] read_addr,
  input      [ADDR_WIDTH-1:0] write_addr,
  input                       write_enable,
  output reg [DATA_WIDTH-1:0] data_out
);

  reg [DATA_WIDTH-1:0] ram [2][2**ADDR_WIDTH-1:0];
    
  always @(posedge clock) begin //WRITE
    if (write_enable) begin 
      ram[buffer_select][write_addr] <= data_in;
    end

    data_out <= ram[1-buffer_select][read_addr];
  end
    
endmodule
