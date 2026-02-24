//-------------------------------------------------------------------------
//  COPYRIGHT (C) 2016  Univ. of Nebraska - Lincoln
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License along
//  with this program; if not, write to the Free Software Foundation, Inc.,
//  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//-------------------------------------------------------------------------
// Title       : rj45_led_controller
// Author      : Caleb Fangmeier
// Created     : Aug. 24, 2016
// Description : This is an interface implementation for controlling a series
//               of eight LEDs on the 8xRJ-45 jack on the Telescope DAQ Board
//               The physical controller is a TLC59282 constant-current LED
//               driver.
//
//               It works by shifting 16 bits into a register on the
//               chip and then latching the value of the shift register into
//               the active register. This controller simply adapts the interface
//               to a simple 8-bit parallel value, and a clock. When the 8-bit
//               value changes, on the next clock a write is initiated.
//
// $Id$
//-------------------------------------------------------------------
`default_nettype none
`timescale 1ns / 1ps

module rj45_led_controller(
  input  wire         clk,  // 150 MHz
  input  wire         reset,

  //--------------------------------------------------------------------------
  //------------------------CONTROL INTERFACE---------------------------------
  //--------------------------------------------------------------------------
  input  wire        write_req,
  input  wire        read_req,
  input  wire [31:0] data_write,
  output reg  [31:0] data_read,
  input  wire [25:0] address,
  output wire        busy,

  //--------------------------------------------------------------------------
  //---------------------------HW INTERFACE-----------------------------------
  //--------------------------------------------------------------------------
  output wire         rj45_led_sck,
  output wire         rj45_led_sin,
  output wire         rj45_led_lat,
  output wire         rj45_led_blk
);

//----------------------------------------------------------------------------
// Parameters
//----------------------------------------------------------------------------
localparam IDLE   = 3'd0,
           READ   = 3'd1,
           WRITE  = 4'd2;
localparam CLK_DIV = 3;

//----------------------------------------------------------------------------
// Wires
//----------------------------------------------------------------------------
wire update_out;

//----------------------------------------------------------------------------
// Registers
//----------------------------------------------------------------------------
reg [CLK_DIV:0] clk_div1;
reg [CLK_DIV:0] clk_div2;
reg             clk_enable;
reg [15:0]      output_shifter;
reg [4:0]       write_counter;
reg             latch;

reg [2:0]       state;
reg             busy_int;
reg [31:0]      value_cache;

//----------------------------------------------------------------------------
// Assignments
//----------------------------------------------------------------------------
assign rj45_led_sck = clk_div2[CLK_DIV] & clk_enable;
assign rj45_led_sin = output_shifter[15];
assign rj45_led_lat = latch;
assign rj45_led_blk = 0;

assign update_out = ~clk_div1[CLK_DIV] & clk_div2[CLK_DIV]; // negedge serial clock
assign busy = busy_int | read_req | write_req;

//----------------------------------------------------------------------------
// Clock Division
//----------------------------------------------------------------------------
always @( posedge clk ) begin
  if ( reset ) begin
    clk_div1 <= 0;
    clk_div2 <= 0;
  end
  else begin
    clk_div2 <= clk_div1;
    clk_div1 <= clk_div1 + 1;
  end
end

//----------------------------------------------------------------------------
// State Machine
//----------------------------------------------------------------------------
always @( posedge clk ) begin
  if ( reset ) begin
    state <= IDLE;
    clk_enable <= 0;
    output_shifter <= 16'h0000;
    write_counter <= 5'h00;
    latch <= 0;
    busy_int <= 1;
    value_cache <= 32'd0;
  end
  else begin
    case ( state )
      IDLE: begin
        data_read <= 32'd0;
        if ( write_req ) begin
          state <= WRITE;
          busy_int <= 1;
          output_shifter <= {1'b0, data_write[0], 1'b0, data_write[1],
                             1'b0, data_write[2], 1'b0, data_write[3],
                             1'b0, data_write[4], 1'b0, data_write[5],
                             1'b0, data_write[6], 1'b0, data_write[7]};
          value_cache <= {24'd0, data_write[7:0]};
          write_counter <= 0;

        end
        else if ( read_req ) begin
          state <= READ;
          busy_int <= 1;
        end
        else begin
          busy_int <= 0;
        end
      end
      WRITE: begin
        if ( update_out ) begin
          write_counter <= write_counter + 5'd1;
          if ( write_counter == 0 ) begin
            clk_enable <= 1;
          end
          else if ( write_counter < 5'd16) begin
            output_shifter <= {output_shifter[14:0], 1'b0};
          end
          else if ( write_counter == 5'd16 ) begin
            clk_enable <= 0;
            latch <= 1;
          end
          else begin
            state <= IDLE;
            latch <= 0;
            busy_int <= 0;
          end
        end
      end
      READ: begin
        state <= IDLE;
        busy_int <= 0;
        data_read <= value_cache;
      end
    endcase
  end
end

endmodule
