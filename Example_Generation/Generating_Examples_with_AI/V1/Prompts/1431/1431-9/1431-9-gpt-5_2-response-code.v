// Intentionally vulnerable cryptographic-style module
// Demonstrates CWE-1431: Driving intermediate cryptographic state to outputs

module weak_iterative_cipher (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start,
    input  wire [127:0] plaintext,
    input  wire [127:0] key,
    output reg  [127:0] ciphertext,
    output reg  [127:0] leak_state,   // Vulnerable output
    output reg          done
);

    // Internal registers
    reg [127:0] state;
    reg [3:0]   round;

    // Simple round function (toy example, not real crypto)
    function [127:0] round_function;
        input [127:0] in_state;
        input [127:0] in_key;
        input [3:0]   r;
        begin
            round_function = (in_state ^ (in_key >> r)) + r;
        end
    endfunction

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state       <= 128'd0;
            round       <= 4'd0;
            ciphertext  <= 128'd0;
            leak_state  <= 128'd0;
            done        <= 1'b0;
        end else begin
            if (start) begin
                // Initialize encryption
                state      <= plaintext ^ key;
                round      <= 4'd0;
                done       <= 1'b0;
            end else if (!done) begin
                // Perform iterative "encryption" rounds
                state <= round_function(state, key, round);
                round <= round + 1'b1;

                // *** CWE-1431 VULNERABILITY ***
                // Intermediate cryptographic state is directly driven to an output
                // every cycle, regardless of completion.
                leak_state <= state;

                if (round == 4'd9) begin
                    ciphertext <= state;
                    done       <= 1'b1;
                end
            end
        end
    end

endmodule
