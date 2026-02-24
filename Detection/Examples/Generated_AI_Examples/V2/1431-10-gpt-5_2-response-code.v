module spn_cipher_core #(
    parameter DATA_WIDTH  = 128,
    parameter KEY_WIDTH   = 128,
    parameter NUM_ROUNDS  = 8
)(
    input                       clk,
    input                       rst_n,
    input                       start,
    input  [DATA_WIDTH-1:0]     plaintext_i,
    input  [KEY_WIDTH-1:0]      key_i,
    output reg [DATA_WIDTH-1:0] ciphertext_o,
    output reg                  valid_o,
    output reg                  busy_o,
    output [DATA_WIDTH-1:0]     debug_state_o   // <-- Leaks intermediate state
);

    //========================================================
    // FSM State Encoding
    //========================================================
    localparam IDLE  = 2'b00;
    localparam LOAD  = 2'b01;
    localparam ROUND = 2'b10;
    localparam DONE  = 2'b11;

    reg [1:0] state_q, state_d;

    //========================================================
    // Internal Registers
    //========================================================
    reg [DATA_WIDTH-1:0] state_q_data, state_d_data;
    reg [KEY_WIDTH-1:0]  round_key_q, round_key_d;
    reg [$clog2(NUM_ROUNDS+1)-1:0] round_cnt_q, round_cnt_d;

    //========================================================
    // Simple S-box (4-bit substitution replicated)
    //========================================================
    function [3:0] sbox4;
        input [3:0] in;
        begin
            case (in)
                4'h0: sbox4 = 4'hE;
                4'h1: sbox4 = 4'h4;
                4'h2: sbox4 = 4'hD;
                4'h3: sbox4 = 4'h1;
                4'h4: sbox4 = 4'h2;
                4'h5: sbox4 = 4'hF;
                4'h6: sbox4 = 4'hB;
                4'h7: sbox4 = 4'h8;
                4'h8: sbox4 = 4'h3;
                4'h9: sbox4 = 4'hA;
                4'hA: sbox4 = 4'h6;
                4'hB: sbox4 = 4'hC;
                4'hC: sbox4 = 4'h5;
                4'hD: sbox4 = 4'h9;
                4'hE: sbox4 = 4'h0;
                4'hF: sbox4 = 4'h7;
            endcase
        end
    endfunction

    //========================================================
    // Substitution Layer
    //========================================================
    integer i;
    reg [DATA_WIDTH-1:0] sub_bytes;

    always @(*) begin
        for (i = 0; i < DATA_WIDTH/4; i = i + 1) begin
            sub_bytes[i*4 +: 4] = sbox4(state_q_data[i*4 +: 4]);
        end
    end

    //========================================================
    // Permutation Layer (bit rotation)
    //========================================================
    wire [DATA_WIDTH-1:0] permuted;
    assign permuted = {sub_bytes[DATA_WIDTH-2:0], sub_bytes[DATA_WIDTH-1]};

    //========================================================
    // Round Key Update (simple rotation and XOR constant)
    //========================================================
    wire [KEY_WIDTH-1:0] next_round_key;
    assign next_round_key = {round_key_q[KEY_WIDTH-2:0], round_key_q[KEY_WIDTH-1]} 
                            ^ {{(KEY_WIDTH-8){1'b0}}, 8'h1B};

    //========================================================
    // Next-State Logic
    //========================================================
    always @(*) begin
        state_d       = state_q;
        state_d_data  = state_q_data;
        round_key_d   = round_key_q;
        round_cnt_d   = round_cnt_q;

        valid_o = 1'b0;
        busy_o  = 1'b1;

        case (state_q)
            IDLE: begin
                busy_o = 1'b0;
                if (start) begin
                    state_d = LOAD;
                end
            end

            LOAD: begin
                state_d_data = plaintext_i ^ key_i;
                round_key_d  = key_i;
                round_cnt_d  = 0;
                state_d      = ROUND;
            end

            ROUND: begin
                state_d_data = permuted ^ round_key_q;
                round_key_d  = next_round_key;
                round_cnt_d  = round_cnt_q + 1;

                if (round_cnt_q == NUM_ROUNDS-1) begin
                    state_d = DONE;
                end
            end

            DONE: begin
                valid_o = 1'b1;
                state_d = IDLE;
            end
        endcase
    end

    //========================================================
    // Sequential Logic
    //========================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state_q      <= IDLE;
            state_q_data <= {DATA_WIDTH{1'b0}};
            round_key_q  <= {KEY_WIDTH{1'b0}};
            round_cnt_q  <= 0;
            ciphertext_o <= {DATA_WIDTH{1'b0}};
        end else begin
            state_q      <= state_d;
            state_q_data <= state_d_data;
            round_key_q  <= round_key_d;
            round_cnt_q  <= round_cnt_d;

            if (state_q == DONE) begin
                ciphertext_o <= state_q_data;
            end
        end
    end

    //========================================================
    // CWE-1431 WEAKNESS:
    // Intermediate state is directly exposed continuously
    //========================================================
    assign debug_state_o = state_q_data;  // <-- Leaks intermediate round state

endmodule
