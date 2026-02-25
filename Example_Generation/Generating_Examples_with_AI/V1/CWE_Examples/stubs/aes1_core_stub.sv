module aes1_core (
    input  logic         clk,
    input  logic         reset_n,

    input  logic         encdec,
    input  logic         init,
    input  logic         next,
    output logic         ready,

    input  logic [255:0] key,
    input  logic [1:0]   keylen,

    input  logic [127:0] block,
    output logic [127:0] result,
    output logic         result_valid
);
    // Stub: no logic
endmodule
