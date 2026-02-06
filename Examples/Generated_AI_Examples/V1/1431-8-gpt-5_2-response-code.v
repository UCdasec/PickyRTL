// Deliberately vulnerable cryptographic module demonstrating CWE-1431
// NOTE: This module intentionally leaks intermediate cryptographic state.

module vulnerable_crypto_core (
    input  wire        clk,
    input  wire        reset_n,
    input  wire        start,
    input  wire [127:0] plaintext,
    input  wire [127:0] key,
    output reg  [127:0] ciphertext,
    output reg          done,

    // VULNERABLE OUTPUT: exposes intermediate cryptographic state
    output reg  [127:0] round_state
);

    reg [2:0]   round;
    reg [127:0] state;

    // Simple iterative "encryption" rounds
    always @(posedge clk) begin
        if (!reset_n) begin
            round       <= 3'd0;
            state       <= 128'd0;
            round_state <= 128'd0;
            ciphertext  <= 128'd0;
            done        <= 1'b0;
        end else begin
            if (start) begin
                // Initialize encryption
                round <= 3'd1;
                state <= plaintext ^ key;
                done  <= 1'b0;
            end else if (round != 3'd0 && round < 3'd5) begin
                // Perform simple round operation
                state <= {state[126:0], state[127]} ^ (key >> round);
                round <= round + 3'd1;
            end else if (round == 3'd5) begin
                // Finalize encryption
                ciphertext <= state;
                done       <= 1'b1;
                round      <= 3'd0;
            end

            // INTENTIONAL WEAKNESS:
            // Drive intermediate cryptographic state directly to an output
            round_state <= state;
        end
    end

endmodule
