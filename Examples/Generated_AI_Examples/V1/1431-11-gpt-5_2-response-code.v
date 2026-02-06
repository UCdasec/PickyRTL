module simple_crypto_core_with_leakage (
    input  wire        clk,
    input  wire        rst,
    input  wire        start,
    input  wire [127:0] plaintext_i,
    input  wire [127:0] key_i,
    output wire [127:0] ciphertext_o,
    output wire        valid_o
);

    // Total number of encryption rounds
    localparam integer TOTAL_ROUNDS = 8;

    reg [3:0]   round_ctr_q;
    reg [127:0] state_q;
    reg [127:0] key_q;

    // Simple round function (toy crypto logic)
    wire [127:0] state_next;
    assign state_next = (state_q ^ key_q) + round_ctr_q;

    // Sequential logic
    always @(posedge clk) begin
        if (rst) begin
            round_ctr_q <= 0;
            state_q     <= 0;
            key_q       <= 0;
        end else if (start) begin
            round_ctr_q <= 0;
            state_q     <= plaintext_i;
            key_q       <= key_i;
        end else if (round_ctr_q < TOTAL_ROUNDS) begin
            state_q     <= state_next;
            key_q       <= {key_q[126:0], key_q[127]}; // simple key rotation
            round_ctr_q <= round_ctr_q + 1;
        end
    end

    // Indicates completion of all rounds
    assign valid_o = (round_ctr_q == TOTAL_ROUNDS);

    // CWE-1431 WEAKNESS:
    // Intermediate cryptographic state is directly driven to the output
    assign ciphertext_o = state_q;

endmodule
