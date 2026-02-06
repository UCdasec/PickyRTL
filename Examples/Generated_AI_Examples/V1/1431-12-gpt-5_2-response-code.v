module toy_cipher_with_state_leak
(
    input  wire        clk,
    input  wire        rst,
    input  wire        start,
    input  wire [127:0] plaintext_i,
    input  wire [127:0] key_i,

    output wire [127:0] ciphertext_o,
    output wire [127:0] debug_state_o,   // <-- Vulnerable output
    output wire        valid_o
);

    // Number of encryption rounds
    localparam integer TOTAL_ROUNDS = 8;

    reg [3:0]   round_q;
    reg [127:0] state_q;
    reg [127:0] key_q;

    wire [127:0] state_next;
    wire [127:0] key_next;

    // Simple "round function" (toy, not real crypto)
    assign state_next = (state_q ^ key_q) + round_q;
    assign key_next   = {key_q[126:0], key_q[127]} ^ round_q;

    always @(posedge clk) begin
        if (rst) begin
            round_q <= 4'd0;
            state_q <= 128'd0;
            key_q   <= 128'd0;
        end else begin
            if (start) begin
                round_q <= 4'd1;
                state_q <= plaintext_i;
                key_q   <= key_i;
            end else if (round_q != 0 && round_q < TOTAL_ROUNDS) begin
                state_q <= state_next;
                key_q   <= key_next;
                round_q <= round_q + 1'b1;
            end else if (round_q == TOTAL_ROUNDS) begin
                round_q <= 4'd0; // Done
            end
        end
    end

    // Ciphertext is only considered valid at the final round
    assign valid_o = (round_q == TOTAL_ROUNDS);

    // Final output
    assign ciphertext_o = valid_o ? state_q : 128'd0;

    // ============================================================
    // CWE-1431 WEAKNESS:
    // Exposes the INTERNAL intermediate cryptographic state
    // on a hardware output during all rounds.
    // ============================================================
    assign debug_state_o = state_q;

endmodule
