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
input logic [7 :0]             reglk_ctrl_i;
input logic                    acct_ctrl_i;
input logic                    debug_mode_i;
input  ariane_axi::req_t       axi_req_i;
output ariane_axi::resp_t      axi_resp_o;

input logic rst_2;

  // ----------------------------------------------------------------
  // Registers
  // ----------------------------------------------------------------
  logic  init_reg, init_reg_d;
  logic  next_reg, next_reg_d;

  logic  encdec_reg;
  logic  keylen_reg, keylen_reg0, keylen_reg1, keylen_reg2;

  logic  [31 : 0] block_reg [0 : 3];
  logic           block_we;

  logic  [31 : 0] key_reg0 [0 : 7];
  logic  [31 : 0] key_reg1 [0 : 7];
  logic  [31 : 0] key_reg2 [0 : 7];
  logic           key_we0, key_we1, key_we2;
  logic  [1:0]    key_sel; 

  // ----------------------------------------------------------------
  // Reset and write logic
  // ----------------------------------------------------------------
  always @(posedge clk_i)
    begin
      integer i;
      if(~(rst_ni && ~rst_2))
        begin
          encdec_reg   <= 1'b0; 
          keylen_reg0  <= 1'b0;
          keylen_reg1  <= 1'b0;
          keylen_reg2  <= 1'b0;
          init_reg     <= 1'b0;
          next_reg     <= 1'b0;
          init_reg_d   <= 1'b0;
          next_reg_d   <= 1'b0;
          key_sel      <= 2'b0;

          // block registers still cleared
          for (i = 0 ; i < 4 ; i = i + 1)
            block_reg[i] <= 32'h0;

          // CWE-226: key registers are NOT cleared on reset
          for (i = 0 ; i < 8 ; i = i + 1) begin
            key_reg0[i] <= key_reg0[i];
            key_reg1[i] <= key_reg1[i];
            key_reg2[i] <= key_reg2[i];
          end
        end
      else if(en && we) begin
        case(address[11:3])
          CTRL_ENCDEC : encdec_reg <= reglk_ctrl_i[1] ? encdec_reg : wdata;
          CTRL_KEYLEN0: keylen_reg0 <= reglk_ctrl_i[3] ? keylen_reg0 : wdata;
          CTRL_KEYLEN1: keylen_reg1 <= reglk_ctrl_i[3] ? keylen_reg1 : wdata;
          CTRL_KEYLEN2: keylen_reg2 <= reglk_ctrl_i[3] ? keylen_reg2 : wdata;
          ADDR_CTRL :
            begin
              init_reg <= reglk_ctrl_i[1] ? init_reg : wdata[0];
              next_reg <= reglk_ctrl_i[1] ? next_reg : wdata[1];
            end  
          KEY_SEL: key_sel <= reglk_ctrl_i[5] ? key_sel : wdata;
          default: ;
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

  // ----------------------------------------------------------------
  // AES core instantiation
  // ----------------------------------------------------------------
  aes1_core core1(
    .clk(clk_i),
    .reset_n(rst_ni && ~rst_2),
    .encdec(encdec_reg),
    .init(init_reg & ~init_reg_d),
    .next(next_reg & ~next_reg_d),
    .ready(core_ready),
    .key(core_key),
    .keylen(core_keylen),
    .block(core_block),
    .result(core_result),
    .result_valid(core_valid)
  );

endmodule