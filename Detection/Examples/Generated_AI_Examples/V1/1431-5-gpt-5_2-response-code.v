module leaky_crypto_core (
    input              clk,
    input              rst,
    input              start,
    input      [127:0]  data_i,
    input      [127:0]  key_i,
    output     [127:0]  data_o,
    output             valid
);

    // Simple multi-round "encryption" parameters
    localparam TOTAL_ROUNDS = 8;

    reg [3:0]   round_q;
    reg [127:0] state_q;
    reg         valid_q;

    // Sequential logic implementing a toy round-based cipher
    always @(posedge clk) begin
        if (rst) begin
            round_q <= 4'd0;
            state_q <= 128'd0;
            valid_q <= 1'b0;
        end else begin
            if (start) begin
                // Initialize encryption
                round_q <= 4'd0;
                state_q <= data_i ^ key_i;  // Initial mixing
                valid_q <= 1'b0;
            end else if (round_q < TOTAL_ROUNDS) begin
                // Each round updates internal cryptographic state
                round_q <= round_q + 1'b1;
                state_q <= {state_q[126:0], state_q[127]} ^ key_i;
                valid_q <= 1'b0;
            end else begin
                // Encryption complete
                valid_q <= 1'b1;
            end
        end
    end

    // ============================================================
    // CWE-1431 WEAKNESS:
    // The intermediate cryptographic state is continuously driven
    // to the output, even when valid_q is LOW.
    // ============================================================
    assign data_o = state_q;

    assign valid  = valid_q;

endmodule
