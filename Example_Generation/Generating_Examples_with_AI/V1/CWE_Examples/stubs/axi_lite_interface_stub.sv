module axi_lite_interface #(
  parameter int unsigned AXI_ADDR_WIDTH = 64,
  parameter int unsigned AXI_DATA_WIDTH = 64,
  parameter int unsigned AXI_ID_WIDTH   = 10
)(
  input  logic clk_i,
  input  logic rst_ni,

  // Use plain logic for stubbed AXI types to avoid package resolution issues.
  input  logic [0:0] axi_req_i,
  output logic [0:0] axi_resp_o,

  output logic [AXI_ADDR_WIDTH-1:0] address_o,
  output logic en_o,
  output logic we_o,
  input  logic [63:0] data_i,
  output logic [63:0] data_o
);
  // Stub: no logic
endmodule
