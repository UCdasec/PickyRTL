//======================================================================
//
// aes1.v
// --------
// Top level wrapper for the AES block cipher core.
//
//======================================================================

module aes1_wrapper #(
    parameter int unsigned AXI_ADDR_WIDTH = 64,
    parameter int unsigned AXI_DATA_WIDTH = 64,
    parameter int unsigned AXI_ID_WIDTH   = 10
)(
          clk_i,
          rst_ni,
          reglk_ctrl_i,
          acct_ctrl_i,
          debug_mode_i,
          axi_req_i, 
          axi_resp_o,
          rst_2
          );
 
input logic                    clk_i;
input logic                    rst_ni;
input logic [7 :0]             reglk_ctrl_i; // register lock values
input logic                    acct_ctrl_i;
input logic                    debug_mode_i;
input  ariane_axi::req_t       axi_req_i;
output ariane_axi::resp_t      axi_resp_o;

input logic rst_2;

  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  localparam ADDR_NAME0       = 9'h00;
  localparam ADDR_NAME1       = 9'h01;
  localparam ADDR_VERSION     = 9'h02;

  localparam ADDR_CTRL        = 9'h08;
  localparam CTRL_INIT_BIT    = 0;
  localparam CTRL_NEXT_BIT    = 1;

  localparam ADDR_STATUS      = 9'h09;
  localparam STATUS_READY_BIT = 0;
  localparam STATUS_VALID_BIT = 1;

  localparam ADDR_CONFIG      = 9'h0a;
  localparam CTRL_ENCDEC   = 9'h0a;
  localparam CTRL_KEYLEN0  = 9'h0b;
  localparam CTRL_KEYLEN1  = 9'h0c;
  localparam CTRL_KEYLEN2  = 9'h0d;

  localparam KEY_SEL           = 9'h0e;
  localparam ADDR_KEY00        = 9'h10;
  localparam ADDR_KEY07        = 9'h17;
  localparam ADDR_KEY10        = 9'h20;
  localparam ADDR_KEY17        = 9'h27;
  localparam ADDR_KEY20        = 9'h30;
  localparam ADDR_KEY27        = 9'h37;

  localparam ADDR_BLOCK0      = 9'h40;
  localparam ADDR_BLOCK3      = 9'h43;

  localparam ADDR_RESULT0     = 9'h50;
  localparam ADDR_RESULT1     = 9'h51;
  localparam ADDR_RESULT2     = 9'h52;
  localparam ADDR_RESULT3     = 9'h53;

  localparam CORE_NAME0       = 32'h61657320; // "aes "
  localparam CORE_NAME1       = 32'h20202020; // "    "
  localparam CORE_VERSION     = 32'h302e3630; // "0.60"

  //----------------------------------------------------------------
  // Registers
  //----------------------------------------------------------------
  logic  init_reg, init_reg_d;
  logic  next_reg, next_reg_d;

  logic  encdec_reg;
  logic  keylen_reg0, keylen_reg1, keylen_reg2;

  logic  [31 : 0] block_reg [0 : 3];
  logic           block_we;

  logic  [31 : 0] key_reg0 [0 : 7];
  logic  [31 : 0] key_reg1 [0 : 7];
  logic  [31 : 0] key_reg2 [0 : 7];
  logic           key_we0, key_we1, key_we2;
  logic  [1:0]    key_sel; 

  //----------------------------------------------------------------
  // AXI signals
  //----------------------------------------------------------------
  logic [AXI_ADDR_WIDTH-1:0] address;
  logic                      en, en_acct;
  logic                      we;
  logic [63:0]               wdata;
  logic [63:0]               rdata;

  assign key_we0  = ((address[11:3] >= ADDR_KEY00) && (address[11:3] <= ADDR_KEY07));
  assign key_we1  = ((address[11:3] >= ADDR_KEY10) && (address[11:3] <= ADDR_KEY17));
  assign key_we2  = ((address[11:3] >= ADDR_KEY20) && (address[11:3] <= ADDR_KEY27));
  assign block_we = ((address[11:3] >= ADDR_BLOCK0) && (address[11:3] <= ADDR_BLOCK3));

  axi_lite_interface #(
        .AXI_ADDR_WIDTH ( AXI_ADDR_WIDTH ),
        .AXI_DATA_WIDTH ( AXI_DATA_WIDTH ),
        .AXI_ID_WIDTH   ( AXI_ID_WIDTH   )
  ) axi_lite_interface_i (
        .clk_i      ( clk_i      ),
        .rst_ni     ( rst_ni     ),
        .axi_req_i  ( axi_req_i  ),
        .axi_resp_o ( axi_resp_o ),
        .address_o  ( address    ),
        .en_o       ( en_acct    ),
        .we_o       ( we         ),
        .data_i     ( rdata      ),
        .data_o     ( wdata      )
  );

  assign en = en_acct && acct_ctrl_i; 

  //----------------------------------------------------------------
  // Register write logic
  //----------------------------------------------------------------
  always @(posedge clk_i) begin
    integer i;
    if (~(rst_ni && ~rst_2)) begin
      encdec_reg  <= 1'b0;
      keylen_reg0 <= 1'b0;
      keylen_reg1 <= 1'b0;
      keylen_reg2 <= 1'b0;
      init_reg    <= 1'b0;
      next_reg    <= 1'b0;
      key_sel     <= 2'b0;

      for (i = 0; i < 4; i = i + 1)
        block_reg[i] <= 32'h0;

      for (i = 0; i < 8; i = i + 1) begin
        key_reg0[i] <= 32'h0;
        key_reg1[i] <= 32'h0;
        key_reg2[i] <= 32'h0;
      end
    end
    else if (en && we) begin
      case (address[11:3])
        // CWE-1233 INSERTION:
        // encdec_reg is now writable even when the lock bit is set
        CTRL_ENCDEC  : encdec_reg  <= wdata;

        CTRL_KEYLEN0 : keylen_reg0 <= reglk_ctrl_i[3] ? keylen_reg0 : wdata;
        CTRL_KEYLEN1 : keylen_reg1 <= reglk_ctrl_i[3] ? keylen_reg1 : wdata;
        CTRL_KEYLEN2 : keylen_reg2 <= reglk_ctrl_i[3] ? keylen_reg2 : wdata;

        ADDR_CTRL : begin
          init_reg <= reglk_ctrl_i[1] ? init_reg : wdata[CTRL_INIT_BIT];
          next_reg <= reglk_ctrl_i[1] ? next_reg : wdata[CTRL_NEXT_BIT];
        end

        KEY_SEL : key_sel <= reglk_ctrl_i[5] ? key_sel : wdata;
        default : ;
      endcase

      if (block_we)
        block_reg[address[4:3]] <= reglk_ctrl_i[5] ? block_reg[address[4:3]] : wdata;

      if (key_we0)
        key_reg0[address[5:3]] <= reglk_ctrl_i[3] ? key_reg0[address[5:3]] : wdata;
      if (key_we1)
        key_reg1[address[5:3]] <= reglk_ctrl_i[3] ? key_reg1[address[5:3]] : wdata;
      if (key_we2)
        key_reg2[address[5:3]] <= reglk_ctrl_i[3] ? key_reg2[address[5:3]] : wdata;
    end
  end

endmodule