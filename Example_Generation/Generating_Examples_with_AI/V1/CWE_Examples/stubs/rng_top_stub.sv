module rng_top (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        load_i,

    input  logic [127:0] seed_i,
    input  logic [127:0] poly128_i,
    input  logic [63:0]  poly64_i,
    input  logic [31:0]  poly32_i,
    input  logic [15:0]  poly16_i,

    output logic [127:0] rand_num_o,
    output logic         rand_num_valid_o,

    // debug / entropy source visibility
    output logic [127:0] seed128_o,
    output logic [63:0]  seed64_o,
    output logic [31:0]  seed32_o,
    output logic [15:0]  seed16_o,

    output logic [127:0] rand_seg128_o,
    output logic [63:0]  rand_seg64_o,
    output logic [31:0]  rand_seg32_o,
    output logic [15:0]  rand_seg16_o,

    output logic [31:0]  cs_state_o
);
    // Stub: no logic
endmodule
