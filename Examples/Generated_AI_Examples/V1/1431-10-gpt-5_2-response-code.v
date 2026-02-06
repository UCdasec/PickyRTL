module simple_crypto_with_leakage (
    input  wire        clk,
    input  wire        rst,
    input  wire        start,
    input  wire [127:0] plaintext_i,
    input  wire [127:0] key_i,
    output wire [127:0] ciphertext_o,
    output wire        done
);

    // Number of rounds for the toy crypto operation
    localparam integer TOTAL_ROUNDS = 8;

    reg [3:0]   round_ctr;
    reg [127:0] data_state;
    reg [127:0] key_state;

    // Simple "round function":
    // XOR with key and rotate left by 1 bit
    wire [127:0] next_data_state;
    wire [127:0] next_key_state;

    assign next_data_state = {data_state[126:0], data_state[127]} ^ key_state;
    assign next_key_state  = {key_state[120:0], key_state[127:121]};

    always @(posedge clk) begin
        if (rst) begin
            round_ctr <= 0;
            data_state <= 0;
            key_state  <= 0;
        end else if (start) begin
            round_ctr <= 0;
            data_state <= plaintext_i;
            key_state  <= key_i;
        end else if (round_ctr < TOTAL_ROUNDS) begin
            data_state <= next_data_state;
            key_state  <= next_key_state;
            round_ctr  <= round_ctr + 1;
        end
    end

    assign done = (round_ctr == TOTAL_ROUNDS);

    // CWE-1431 WEAKNESS:
    // Intermediate cryptographic state is always driven to the output
    assign ciphertext_o = data_state;

endmodule
