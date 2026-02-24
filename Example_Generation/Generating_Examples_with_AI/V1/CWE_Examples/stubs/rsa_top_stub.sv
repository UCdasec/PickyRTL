module rsa_top #(
    parameter int unsigned WIDTH = 32
)(
    input  logic                   clk,
    input  logic                   rst_n,
    input  logic                   rst1_n,

    input  logic                   encrypt_decrypt_i,

    input  logic [WIDTH-1:0]       p_i,
    input  logic [WIDTH-1:0]       q_i,

    input  logic [WIDTH*2-1:0]     msg_in,
    output logic [WIDTH*2-1:0]     msg_out,

    output logic                   mod_exp_finish_o
);
    // Stub: no logic
endmodule
