`timescale 1ns / 1ps

module simple_spn_cipher #(
    parameter DATA_WIDTH  = 128,
    parameter KEY_WIDTH   = 128,
    parameter NUM_ROUNDS  = 4
)(
    input                       clk,
    input                       rst_n,
    input                       start,
    input  [DATA_WIDTH-1:0]     plaintext,
    input  [KEY_WIDTH-1:0]      key,
    output reg [DATA_WIDTH-1:0] ciphertext,
    output reg                  done,
    output reg                  busy,
    output reg [DATA_WIDTH-1:0] round_state_out  // CWE-1431 vulnerability
);

    // FSM states
    localparam STATE_IDLE    = 2'd0;
    localparam STATE_PROCESS = 2'd1;
    localparam STATE_DONE    = 2'd2;

    reg [1:0] state, next_state;

    // Round counter
    reg [$clog2(NUM_ROUNDS):0] round_counter;

    // Internal storage
    reg [DATA_WIDTH-1:0] state_reg;      // Current cipher state
    reg [DATA_WIDTH-1:0] sub_bytes_out;  // Stage 1 result
    reg [DATA_WIDTH-1:0] perm_out;       // Stage 2 result
    reg [DATA_WIDTH-1:0] key_mix_out;    // Stage 3 result

    // Simple S-box (4-bit substitution replicated)
    function [3:0] sbox4;
        input [3:0] in;
        begin
            case (in)
                4'h0: sbox4 = 4'hC;
                4'h1: sbox4 = 4'h5;
                4'h2: sbox4 = 4'h6;
                4'h3: sbox4 = 4'hB;
                4'h4: sbox4 = 4'h9;
                4'h5: sbox4 = 4'h0;
                4'h6: sbox4 = 4'hA;
                4'h7: sbox4 = 4'hD;
                4'h8: sbox4 = 4'h3;
                4'h9: sbox4 = 4'hE;
                4'hA: sbox4 = 4'hF;
                4'hB: sbox4 = 4'h8;
                4'hC: sbox4 = 4'h4;
                4'hD: sbox4 = 4'h7;
                4'hE: sbox4 = 4'h1;
                4'hF: sbox4 = 4'h2;
            endcase
        end
    endfunction

    integer i;

    // FSM state transition
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            state <= STATE_IDLE;
        else
            state <= next_state;
    end

    always @(*) begin
        case (state)
            STATE_IDLE: begin
                if (start)
                    next_state = STATE_PROCESS;
                else
                    next_state = STATE_IDLE;
            end
            STATE_PROCESS: begin
                if (round_counter == NUM_ROUNDS)
                    next_state = STATE_DONE;
                else
                    next_state = STATE_PROCESS;
            end
            STATE_DONE: begin
                next_state = STATE_IDLE;
            end
            default: next_state = STATE_IDLE;
        endcase
    end

    // Round counter
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            round_counter <= 0;
        else if (state == STATE_IDLE && start)
            round_counter <= 0;
        else if (state == STATE_PROCESS)
            round_counter <= round_counter + 1;
    end

    // Cipher processing pipeline
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state_reg       <= 0;
            sub_bytes_out   <= 0;
            perm_out        <= 0;
            key_mix_out     <= 0;
            ciphertext      <= 0;
            busy            <= 0;
            done            <= 0;
            round_state_out <= 0;
        end else begin
            case (state)
                STATE_IDLE: begin
                    done <= 0;
                    busy <= 0;
                    if (start) begin
                        state_reg <= plaintext;
                        busy <= 1;
                    end
                end

                STATE_PROCESS: begin
                    // Stage 1: SubBytes (bit-level substitution)
                    for (i = 0; i < DATA_WIDTH; i = i + 4) begin
                        sub_bytes_out[i +: 4] <= sbox4(state_reg[i +: 4]);
                    end

                    // Stage 2: Simple permutation (rotate left by round_counter bits)
                    perm_out <= {sub_bytes_out[DATA_WIDTH-2:0], sub_bytes_out[DATA_WIDTH-1]};

                    // Stage 3: AddRoundKey
                    key_mix_out <= perm_out ^ (key ^ round_counter);

                    // Update state
                    state_reg <= key_mix_out;

                    // CWE-1431 Vulnerability:
                    // Exposing intermediate round state externally
                    round_state_out <= state_reg;
                end

                STATE_DONE: begin
                    ciphertext <= state_reg;
                    busy <= 0;
                    done <= 1;
                end
            endcase
        end
    end

endmodule
