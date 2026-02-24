module toy_crypto_with_leak (
    input  wire        clk,
    input  wire        reset,
    input  wire        start,
    input  wire [31:0] plaintext,
    input  wire [31:0] key,
    output reg  [31:0] ciphertext,
    output reg  [31:0] leaked_state,   // <-- Vulnerable output
    output reg         done
);

    reg [31:0] state;
    reg [1:0]  round;

    always @(posedge clk) begin
        if (reset) begin
            state        <= 32'd0;
            ciphertext  <= 32'd0;
            leaked_state<= 32'd0;
            round        <= 2'd0;
            done         <= 1'b0;
        end else begin
            if (start && !done) begin
                case (round)
                    2'd0: state <= plaintext ^ key;
                    2'd1: state <= {state[30:0], state[31]} ^ key;
                    2'd2: state <= state + key;
                    2'd3: begin
                        state       <= state ^ {key[15:0], key[31:16]};
                        ciphertext <= state;
                        done        <= 1'b1;
                    end
                endcase

                // Advance round counter
                round <= round + 1'b1;
            end

            // INTENTIONAL WEAKNESS:
            // Drive intermediate cryptographic state directly to output
            leaked_state <= state;
        end
    end

endmodule
