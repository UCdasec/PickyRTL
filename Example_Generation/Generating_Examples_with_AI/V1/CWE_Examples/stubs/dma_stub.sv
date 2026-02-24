module dma #(
  parameter int unsigned DATA_WIDTH   = 32,
  parameter int unsigned NrPMPEntries = 8
)(
  input  logic clk_i,
  input  logic rst_ni,

  input  logic [DATA_WIDTH-1:0] start_i,
  input  logic [DATA_WIDTH-1:0] length_i,
  input  logic [DATA_WIDTH-1:0] source_addr_lsb_i,
  input  logic [DATA_WIDTH-1:0] source_addr_msb_i,
  input  logic [DATA_WIDTH-1:0] dest_addr_lsb_i,
  input  logic [DATA_WIDTH-1:0] dest_addr_msb_i,

  output logic [DATA_WIDTH-1:0] valid_o,
  input  logic [DATA_WIDTH-1:0] done_i,

  input  logic [7:0][15:0]  pmpcfg_i,
  input  logic [15:0][53:0] pmpaddr_i,

  input  logic we_flag
);
  // Stub: no logic
endmodule
