module leaky_crypto_core (
    input  wire        clk,
    input  wire        rst,
    input  wire        start,
    input  wire [127:0] plaintext_i,
    input  wire [127:0] key_i,
    output wire [127:0] ciphertext_o,
    output wire        valid_o
);

    // Simple fixed number of "crypto" rounds
    localparam integer TOTAL_ROUNDS = 8;

    reg [3:0]   round_ctr_q;
    reg [127:0] data_state_q;
    reg [127:0] key_state_q;
    reg         busy_q;

    // Toy round function: XOR with key, then rotate
    wire [127:0] round_data;
    assign round_data = {data_state_q[120:0], data_state_q[127:121]} ^ key_state_q;

    always @(posedge clk) begin
        if (rst) begin
            round_ctr_q <= 4'd0;
            data_state_q <= 128'd0;
            key_state_q <= 128'd0;
            busy_q <= 1'b0;
        end else begin
            if (start && !busy_q) begin
                // Load inputs and start operation
                data_state_q <= plaintext_i;
                key_state_q  <= key_i;
                round_ctr_q  <= 4'd0;
                busy_q       <= 1'b1;
            end else if (busy_q) begin
                // Perform one crypto round per cycle
                data_state_q <= round_data;
                round_ctr_q  <= round_ctr_q + 1'b1;

                if (round_ctr_q == TOTAL_ROUNDS - 1) begin
                    busy_q <= 1'b0;
                end
            end
        end
    end

    // Indicates completion of the cryptographic operation
    assign valid_o = (!busy_q && (round_ctr_q == TOTAL_ROUNDS));

    // CWE-1431 WEAKNESS:
    // Intermediate cryptographic state is always driven to the output,
    // even while rounds are still executing.
    assign ciphertext_o = data_state_q;

endmodule
