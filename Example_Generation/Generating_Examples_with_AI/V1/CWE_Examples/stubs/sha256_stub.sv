module sha256 (
    input  logic        clk,
    input  logic        rst,
    input  logic        init,
    input  logic        next,

    input  logic [511:0] block,

    output logic [255:0] h_block,
    output logic         h_block_update,

    output logic [255:0] digest,
    output logic         digest_valid,
    output logic         ready
);
    // Stub: no logic
endmodule
