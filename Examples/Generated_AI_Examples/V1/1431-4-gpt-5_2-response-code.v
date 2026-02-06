module insecure_crypto_core
(
    input  wire        clk,
    input  wire        rst,
    input  wire        start,
    input  wire [127:0] plaintext_i,
    input  wire [127:0] key_i,
    output wire [127:0] ciphertext_o,
    output wire        done
);

    // Number of "encryption" rounds
    localparam integer TOTAL_ROUNDS = 8;

    reg [3:0]   round_ctr;
    reg [127:0] state_q;
    reg [127:0] key_q;

    // Simple round function (purely illustrative, not real crypto)
    wire [127:0] next_state;
    assign next_state = {state_q[120:0], state_q[127:121]} ^ key_q ^ round_ctr;

    always @(posedge clk) begin
        if (rst) begin
            round_ctr <= 4'd0;
            state_q   <= 128'd0;
            key_q     <= 128'd0;
        end else begin
            if (start) begin
                round_ctr <= 4'd0;
                state_q   <= plaintext_i;
                key_q     <= key_i;
            end else if (round_ctr < TOTAL_ROUNDS) begin
                state_q   <= next_state;
                key_q     <= {key_q[95:0], key_q[127:96]}; // simple key schedule
                round_ctr <= round_ctr + 1'b1;
            end
        end
    end

    assign done = (round_ctr == TOTAL_ROUNDS);

    // CWE-1431 WEAKNESS:
    // Intermediate cryptographic state is always driven to the output
    assign ciphertext_o = state_q;

endmodule
