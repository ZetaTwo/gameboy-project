`default_nettype none

module gameboy_capture_card(
  input wire BTN1, 
  input wire CLK, 

  input wire P1A1, // Pixel clock
  input wire P1A2, // H-sync
  input wire P1A3, // V-sync
  input wire P1A4, // LCD Data 0
  input wire P1A7, // LCD Data 1
  
  output wire LED1,
);
/*
   wire   A, B;
   reg [2:0] out;
   assign {LED2, LED1, LED3} = out;
   assign A = BTN1;
   assign B = BTN2;

  always @ (posedge CLK) begin
    if (A < B)
      out <= 3'b100;
    else if (A == B)
      out <= 3'b010;
    else
      out <= 3'b001;
  end
*/

  wire reset = BTN1;
  wire pixel_clock = P1A1;
  wire h_sync = P1A2;
  wire v_sync = P1A3;
  wire lcd_data0 = P1A4;
  wire lcd_data1 = P1A7;

  wire [14:0] mem_write_addr;
  wire [1:0] pixel_data;
  wire buffer_select;

  wire [14:0] mem_read_addr;
  wire [1:0] pixel_out;

  gameboy_lcd_decoder lcd_decoder(
    .clock(CLK),
    .reset(reset),

    .pixel_clock(pixel_clock),
    .h_sync(h_sync),
    .v_sync(v_sync),
    .lcd_data0(lcd_data0),
    .lcd_data1(lcd_data1),

    .pixel_addr(mem_write_addr),
    .pixel_data(pixel_data),
    .buffer_select(buffer_select)
  );

  gameboy_frame_buffer frame_buffer(
    .clock(CLK),
    .reset(reset),

    .buffer_select(buffer_select),
    .data_in(pixel_data),
    .write_addr(mem_write_addr),
    .write_enable(1),

    .data_out(pixel_out),
    .read_addr(mem_read_addr)
  );

  hdmi_output hdmi(
    .clock(CLK),
    .reset(reset),

    .data_addr(mem_read_addr),
    .pixel_data(pixel_out)
  );

endmodule
