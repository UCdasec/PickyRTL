module pkt #(
    parameter int unsigned FUSE_MEM_SIZE = 0
)(
    input  logic        clk_i,
    input  logic        rst_ni,
    input  logic        req_i,
    input  logic [$clog2(FUSE_MEM_SIZE)-1:0] fuse_indx_i,
    output logic [31:0] pkey_loc_o
);
    // Stub: no logic
endmodule
