module spn_cipher_core #(
    parameter DATA_WIDTH  = 128,
    parameter KEY_WIDTH   = 128,
    parameter NUM_ROUNDS  = 8
)(
    input                       clk,
    input                       rst_n,
    input                       start,
    input      [DATA_WIDTH-1:0] plaintext_i,
    input      [KEY_WIDTH-1:0]  key_i,

    output reg [DATA_WIDTH-1:0] ciphertext_o,
    output reg                  valid_o,
    output reg                  busy_o,

    // Debug/status output (intentionally vulnerable)
    output     [DATA_WIDTH-1:0] round_state_o
);

    // ============================================================
    // FSM State Encoding
    // ============================================================
    localparam ST_IDLE  = 2'd0;
    localparam ST_INIT  = 2'd1;
    localparam ST_ROUND = 2'd2;
    localparam ST_DONE  = 2'd3;

    reg [1:0] state_q, state_d;

    // ============================================================
    // Internal Registers
    // ============================================================
    reg [DATA_WIDTH-1:0] state_q_data, state_d_data;
    reg [KEY_WIDTH-1:0]  round_key_q;
    reg [$clog2(NUM_ROUNDS+1)-1:0] round_cnt_q, round_cnt_d;

    // ============================================================
    // Stage 1: Substitution Layer (bit-level manipulation)
    // Simple nibble-wise inversion as example S-box
    // ============================================================
    wire [DATA_WIDTH-1:0] sub_stage;

    genvar i;
    generate
        for (i = 0; i < DATA_WIDTH; i = i + 4) begin : SBOX_GEN
            assign sub_stage[i +: 4] = ~state_q_data[i +: 4];
        end
    endgenerate

    // ============================================================
    // Stage 2: Permutation Layer (bit rotation)
    // ============================================================
    wire [DATA_WIDTH-1:0] perm_stage;
    assign perm_stage = {sub_stage[DATA_WIDTH-9:0], sub_stage[DATA_WIDTH-1:DATA_WIDTH-8]};

    // ============================================================
    // Stage 3: Key Mixing
    // ============================================================
    wire [DATA_WIDTH-1:0] mix_stage;
    assign mix_stage = perm_stage ^ round_key_q;

    // ============================================================
    // Round Key Update (simple rotation per round)
    // ============================================================
    wire [KEY_WIDTH-1:0] next_round_key;
    assign next_round_key = {round_key_q[KEY_WIDTH-2:0], round_key_q[KEY_WIDTH-1]};

    // ============================================================
    // FSM Sequential Logic
    // ============================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state_q       <= ST_IDLE;
            state_q_data  <= {DATA_WIDTH{1'b0}};
            round_key_q   <= {KEY_WIDTH{1'b0}};
            round_cnt_q   <= 0;
        end else begin
            state_q       <= state_d;
            state_q_data  <= state_d_data;
            round_cnt_q   <= round_cnt_d;

            if (state_q == ST_INIT)
                round_key_q <= key_i;
            else if (state_q == ST_ROUND)
                round_key_q <= next_round_key;
        end
    end

    // ============================================================
    // FSM Combinational Logic
    // ============================================================
    always @(*) begin
        state_d       = state_q;
        state_d_data  = state_q_data;
        round_cnt_d   = round_cnt_q;

        ciphertext_o  = {DATA_WIDTH{1'b0}};
        valid_o       = 1'b0;
        busy_o        = 1'b1;

        case (state_q)
            ST_IDLE: begin
                busy_o = 1'b0;
                if (start) begin
                    state_d      = ST_INIT;
                end
            end

            ST_INIT: begin
                state_d_data = plaintext_i ^ key_i;  // Initial whitening
                round_cnt_d  = 0;
                state_d      = ST_ROUND;
            end

            ST_ROUND: begin
                state_d_data = mix_stage;
                round_cnt_d  = round_cnt_q + 1;

                if (round_cnt_q == NUM_ROUNDS-1) begin
                    state_d = ST_DONE;
                end
            end

            ST_DONE: begin
                ciphertext_o = state_q_data;
                valid_o      = 1'b1;
                busy_o       = 1'b0;
                state_d      = ST_IDLE;
            end
        endcase
    end

    // ============================================================
    // *** CWE-1431 Vulnerability ***
    // Intermediate round state is directly exposed
    // ============================================================
    assign round_state_o = state_q_data;

endmodule
