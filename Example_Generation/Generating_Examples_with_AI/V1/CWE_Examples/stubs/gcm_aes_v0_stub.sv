module gcm_aes_v0 (
    input  logic         clk,
    input  logic         rst,

    // data input interface
    input  logic [127:0] dii_data,
    input  logic         dii_data_vld,
    input  logic [1:0]   dii_data_type,
    input  logic         dii_last_word,
    output logic         dii_data_not_ready,
    input  logic [15:0]  dii_data_size,

    // control input interface
    input  logic         cii_ctl_vld,
    input  logic         cii_IV_vld,
    input  logic [127:0] cii_K,

    // data output interface
    output logic [127:0] Out_data,
    output logic         Out_vld,
    output logic [15:0]  Out_data_size,
    output logic         Out_last_word,

    // tag output interface
    output logic         Tag_vld
);
    // Stub: no logic
endmodule
