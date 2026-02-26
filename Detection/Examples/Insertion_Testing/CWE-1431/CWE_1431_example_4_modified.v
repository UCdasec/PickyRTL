module sha256(
           input wire            clk,
           input wire            rst,

           input wire            init,
           input wire            next,

           input wire [511 : 0]  block,

           input wire [255 : 0]  h_block,
           input wire            h_block_update,

           output wire           ready,
           output wire [255 : 0] digest,
           output wire           digest_valid
       );

//----------------------------------------------------------------
// Internal constant and parameter definitions.
//----------------------------------------------------------------
parameter SHA256_H0_0 = 32'h6a09e667;
parameter SHA256_H0_1 = 32'hbb67ae85;
parameter SHA256_H0_2 = 32'h3c6ef372;
parameter SHA256_H0_3 = 32'ha54ff53a;
parameter SHA256_H0_4 = 32'h510e527f;
parameter SHA256_H0_5 = 32'h9b05688c;
parameter SHA256_H0_6 = 32'h1f83d9ab;
parameter SHA256_H0_7 = 32'h5be0cd19;

parameter SHA256_ROUNDS = 63;

parameter CTRL_IDLE   = 0;
parameter CTRL_ROUNDS = 1;
parameter CTRL_DONE   = 2;
parameter CTRL_IGNORE = 3;

//----------------------------------------------------------------
// Registers including update variables and write enable.
//----------------------------------------------------------------
reg [31 : 0] a_reg;
reg [31 : 0] a_new;
reg [31 : 0] b_reg;
reg [31 : 0] b_new;
reg [31 : 0] c_reg;
reg [31 : 0] c_new;
reg [31 : 0] d_reg;
reg [31 : 0] d_new;
reg [31 : 0] e_reg;
reg [31 : 0] e_new;
reg [31 : 0] f_reg;
reg [31 : 0] f_new;
reg [31 : 0] g_reg;
reg [31 : 0] g_new;
reg [31 : 0] h_reg;
reg [31 : 0] h_new;
reg          a_h_we;

reg [31 : 0] H0_reg;
reg [31 : 0] H0_new;
reg [31 : 0] H1_reg;
reg [31 : 0] H1_new;
reg [31 : 0] H2_reg;
reg [31 : 0] H2_new;
reg [31 : 0] H3_reg;
reg [31 : 0] H3_new;
reg [31 : 0] H4_reg;
reg [31 : 0] H4_new;
reg [31 : 0] H5_reg;
reg [31 : 0] H5_new;
reg [31 : 0] H6_reg;
reg [31 : 0] H6_new;
reg [31 : 0] H7_reg;
reg [31 : 0] H7_new;
reg          H_we;

reg [5 : 0] t_ctr_reg;
reg [5 : 0] t_ctr_new;
reg         t_ctr_we;
reg         t_ctr_inc;
reg         t_ctr_rst;

reg digest_valid_reg;
reg digest_valid_new;
reg digest_valid_we;

reg ignore_input_reg; 
reg ignore_input_new; 
reg ignore_input_en; 

reg [1 : 0] sha256_ctrl_reg;
reg [1 : 0] sha256_ctrl_new;
reg         sha256_ctrl_we;

//----------------------------------------------------------------
// Wires.
//----------------------------------------------------------------
reg digest_init;
reg digest_update;

reg state_init;
reg state_update;

reg first_block;

reg ready_flag;

reg [31 : 0] t1;
reg [31 : 0] t2;

wire [31 : 0] k_data;

reg           w_init;
reg           w_next;
wire [31 : 0] w_data;

//----------------------------------------------------------------
// Module instantiantions.
//----------------------------------------------------------------
sha256_k_constants k_constants_inst(
                       .addr(t_ctr_reg),
                       .K(k_data)
                   );

sha256_w_mem w_mem_inst(
                 .clk(clk),
                 .rst(rst),
                 .block(block),
                 .init(w_init),
                 .next(w_next),
                 .w(w_data)
             );

//----------------------------------------------------------------
// Concurrent connectivity for ports etc.
//----------------------------------------------------------------
assign ready = ready_flag;

/* CWE-1431 INSERTION:
 * Leak intermediate working variables on digest output
 * when digest_valid is low.
 */
assign digest = (digest_valid) ?
                {H0_reg, H1_reg, H2_reg, H3_reg,
                 H4_reg, H5_reg, H6_reg, H7_reg} :
                {a_reg, b_reg, c_reg, d_reg,
                 e_reg, f_reg, g_reg, h_reg};

assign digest_valid = digest_valid_reg;

// ----------------------------------------------------------------
// (Rest of the module remains unchanged)
// ----------------------------------------------------------------

endmodule