module spn_cipher_with_leakage #
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

    // *** Intentional CWE-1431 Weakness: intermediate state exposed ***
    output [DATA_WIDTH-1:0]     round_state_o
);

    // FSM States
    localparam S_IDLE    = 2'd0;
    localparam S_PROCESS = 2'd1;
    localparam S_DONE    = 2'd2;

    reg [1:0] state_q, state_d;

    // Round counter
    reg [$clog2(NUM_ROUNDS+1)-1:0] round_cnt_q, round_cnt_d;

    // Internal state registers
    reg [DATA_WIDTH-1:0] state_q_reg, state_d_reg;
    reg [KEY_WIDTH-1:0]  key_q_reg;

    // Next round key (simple rotation-based derivation)
    wire [KEY_WIDTH-1:0] round_key_w;
    assign round_key_w = {key_q_reg[KEY_WIDTH-9:0], key_q_reg[KEY_WIDTH-1:KEY_WIDTH-8]} 
                         ^ round_cnt_q;

    // --- Substitution layer (simple nibble inversion as example S-box) ---
    function [DATA_WIDTH-1:0] sub_layer;
        input [DATA_WIDTH-1:0] data_in;
        integer i;
        begin
            for (i = 0; i < DATA_WIDTH; i = i + 4) begin
                sub_layer[i +: 4] = ~data_in[i +: 4];
            end
        end
    endfunction

    // --- Permutation layer (simple rotate-left by 3 bits) ---
    function [DATA_WIDTH-1:0] perm_layer;
        input [DATA_WIDTH-1:0] data_in;
        begin
            perm_layer = {data_in[DATA_WIDTH-4:0], data_in[DATA_WIDTH-1:DATA_WIDTH-3]};
        end
    endfunction

    // Combinational next-state logic
    always @(*) begin
        state_d        = state_q;
        round_cnt_d    = round_cnt_q;
        state_d_reg    = state_q_reg;

        case (state_q)
            S_IDLE: begin
                if (start) begin
                    state_d     = S_PROCESS;
                    round_cnt_d = 0;
                    state_d_reg = plaintext_i ^ key_i; // Initial whitening
                end
            end

            S_PROCESS: begin
                if (round_cnt_q < NUM_ROUNDS) begin
                    state_d_reg = perm_layer(sub_layer(state_q_reg)) ^ round_key_w;
                    round_cnt_d = round_cnt_q + 1;
                end
                else begin
                    state_d = S_DONE;
                end
            end

            S_DONE: begin
                state_d = S_IDLE;
            end

            default: begin
                state_d = S_IDLE;
            end
        endcase
    end

    // Sequential logic
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state_q       <= S_IDLE;
            round_cnt_q   <= 0;
            state_q_reg   <= 0;
            key_q_reg     <= 0;
            ciphertext_o  <= 0;
            valid_o       <= 0;
            busy_o        <= 0;
        end
        else begin
            state_q     <= state_d;
            round_cnt_q <= round_cnt_d;
            state_q_reg <= state_d_reg;

            case (state_q)
                S_IDLE: begin
                    valid_o <= 0;
                    busy_o  <= 0;
                    if (start) begin
                        key_q_reg <= key_i;
                        busy_o    <= 1;
                    end
                end

                S_PROCESS: begin
                    busy_o  <= 1;
                    valid_o <= 0;
                end

                S_DONE: begin
                    ciphertext_o <= state_q_reg;
                    valid_o      <= 1;
                    busy_o       <= 0;
                end
            endcase
        end
    end

    // ================================================================
    // CWE-1431 WEAKNESS:
    // Directly exposing intermediate round state to module output
    // ================================================================
    assign round_state_o = state_q_reg;

endmodule
