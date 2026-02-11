module custom_spn_cipher #
(
    parameter DATA_WIDTH  = 128,
    parameter KEY_WIDTH   = 128,
    parameter NUM_ROUNDS  = 8
)
(
    input                       clk,
    input                       rst_n,
    input                       start,
    input  [DATA_WIDTH-1:0]     plaintext_i,
    input  [KEY_WIDTH-1:0]      key_i,

    output reg [DATA_WIDTH-1:0] ciphertext_o,
    output reg                  valid_o,
    output reg                  busy_o,

    // DEBUG / STATUS OUTPUT (Introduces CWE-1431 Weakness)
    output [DATA_WIDTH-1:0]     round_state_o
);

    //===========================================================
    // Internal State and Control
    //===========================================================

    localparam IDLE  = 2'd0;
    localparam ROUND = 2'd1;
    localparam DONE  = 2'd2;

    reg [1:0] state_q, state_d;

    reg [3:0] round_cnt_q, round_cnt_d;

    // Input buffering
    reg [DATA_WIDTH-1:0] state_reg_q, state_reg_d;
    reg [KEY_WIDTH-1:0]  key_reg_q, key_reg_d;

    // Round intermediate signals
    wire [DATA_WIDTH-1:0] addkey_stage;
    wire [DATA_WIDTH-1:0] sbox_stage;
    wire [DATA_WIDTH-1:0] perm_stage;

    //===========================================================
    // Round Function (Substitution-Permutation Network)
    //===========================================================

    // Stage 1: AddRoundKey (XOR)
    assign addkey_stage = state_reg_q ^ key_reg_q;

    // Stage 2: Simple S-box (bitwise inversion as placeholder)
    assign sbox_stage = ~addkey_stage;

    // Stage 3: Permutation (rotate left by round count)
    assign perm_stage = (sbox_stage << round_cnt_q) |
                        (sbox_stage >> (DATA_WIDTH - round_cnt_q));

    //===========================================================
    // FSM Next-State Logic
    //===========================================================

    always @(*) begin
        state_d        = state_q;
        round_cnt_d    = round_cnt_q;
        state_reg_d    = state_reg_q;
        key_reg_d      = key_reg_q;
        valid_o        = 1'b0;
        busy_o         = 1'b1;

        case (state_q)

            IDLE: begin
                busy_o = 1'b0;
                if (start) begin
                    state_reg_d = plaintext_i;  // Input buffering
                    key_reg_d   = key_i;        // Key buffering
                    round_cnt_d = 4'd0;
                    state_d     = ROUND;
                end
            end

            ROUND: begin
                state_reg_d = perm_stage;   // Update intermediate state
                round_cnt_d = round_cnt_q + 1'b1;

                if (round_cnt_q == NUM_ROUNDS-1) begin
                    state_d = DONE;
                end
            end

            DONE: begin
                valid_o = 1'b1;
                busy_o  = 1'b0;
                state_d = IDLE;
            end

            default: begin
                state_d = IDLE;
            end
        endcase
    end

    //===========================================================
    // Sequential Logic
    //===========================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state_q      <= IDLE;
            round_cnt_q  <= 4'd0;
            state_reg_q  <= {DATA_WIDTH{1'b0}};
            key_reg_q    <= {KEY_WIDTH{1'b0}};
            ciphertext_o <= {DATA_WIDTH{1'b0}};
        end
        else begin
            state_q      <= state_d;
            round_cnt_q  <= round_cnt_d;
            state_reg_q  <= state_reg_d;
            key_reg_q    <= key_reg_d;

            if (state_q == DONE) begin
                ciphertext_o <= state_reg_q;
            end
        end
    end

    //===========================================================
    // Intentional CWE-1431 Weakness
    //===========================================================

    // Directly exposing intermediate round state externally
    assign round_state_o = state_reg_q;

endmodule
