module aes2_interface (
    input  logic        clk,
    input  logic [127:0] iv,
    input  logic        rst,
    input  logic        start,
    input  logic [127:0] cii_K,
    input  logic [127:0] input_pc,

    output logic [127:0] Out_data_final,
    output logic        ct_valid_out
);
    // Stub: no logic
endmodule
