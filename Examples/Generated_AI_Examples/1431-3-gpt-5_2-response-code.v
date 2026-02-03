// Deliberately vulnerable cryptographic module demonstrating CWE-1431
// WARNING: This module intentionally leaks intermediate cryptographic state.

module toy_cipher_with_leak (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start,
    input  wire [31:0] plaintext,
    input  wire [31:0] key,
    output reg  [31:0] ciphertext,
    output reg         done,

    // VULNERABLE OUTPUT:
    // Exposes internal round state directly to an output pin
    output reg  [31:0] round_state_out
);

    reg [31:0] state;
    reg [2:0]  round;

    // Simple combinational "round function"
    function [31:0] round_func;
        input [31:0] in;
        input [31:0] k;
        begin
            // Simple mixing: rotate + XOR (toy, not real crypto)
            round_func = {in[23:0], in[31:24]} ^ k;
        end
    endfunction

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state           <= 32'd0;
            round           <= 3'd0;
            ciphertext      <= 32'd0;
            done            <= 1'b0;
            round_state_out <= 32'd0;
        end else begin
            if (start) begin
                // Initialize encryption
                state      <= plaintext;
                round      <= 3'd0;
                done       <= 1'b0;
            end else if (!done) begin
                // Perform encryption rounds
                state <= round_func(state, key ^ round);
                round <= round + 1'b1;

                // INTENTIONAL VULNERABILITY:
                // Intermediate cryptographic state is driven to output
                round_state_out <= state;

                if (round == 3'd3) begin
                    ciphertext <= state;
                    done       <= 1'b1;
                end
            end
        end
    end

endmodule
