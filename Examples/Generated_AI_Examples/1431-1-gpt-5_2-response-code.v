module insecure_xor_cipher (
    input  wire        clk,
    input  wire        reset,
    input  wire        start,
    input  wire [31:0] plaintext,
    input  wire [31:0] key,
    output reg  [31:0] ciphertext,
    output reg  [31:0] leak_state,   // Vulnerable output: leaks intermediate crypto state
    output reg         done
);

    reg [31:0] round_state;
    reg [1:0]  round_count;

    always @(posedge clk) begin
        if (reset) begin
            round_state <= 32'd0;
            ciphertext <= 32'd0;
            leak_state <= 32'd0;
            round_count <= 2'd0;
            done <= 1'b0;
        end else begin
            if (start) begin
                // Initialize encryption
                round_state <= plaintext;
                round_count <= 2'd0;
                done <= 1'b0;
            end else if (!done) begin
                // Simple multi-round XOR "cipher"
                round_state <= round_state ^ (key >> round_count);
                round_count <= round_count + 1'b1;

                // INTENTIONAL VULNERABILITY:
                // Intermediate cryptographic state is directly exposed
                leak_state <= round_state;

                if (round_count == 2'd3) begin
                    ciphertext <= round_state ^ (key >> round_count);
                    done <= 1'b1;
                end
            end
        end
    end

endmodule
