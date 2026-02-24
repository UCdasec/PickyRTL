// Simple Parameterized Substitution-Permutation Network (SPN) Cipher Core
// Intentionally contains CWE-1431: Intermediate cryptographic state is driven to output

module spn_cipher_core #(
    parameter DATA_WIDTH = 32,
    parameter NUM_ROUNDS = 4
)(
    input  wire                     clk,
    input  wire                     rst_n,
    input  wire                     start,
    input  wire [DATA_WIDTH-1:0]    plaintext,
    input  wire [DATA_WIDTH-1:0]    key,
    output reg  [DATA_WIDTH-1:0]    ciphertext,
    output reg                      busy,
    output reg                      done,
    output wire [DATA_WIDTH-1:0]    debug_state  // <-- Vulnerable output
);

    // FSM States
    localparam IDLE  = 2'd0;
    localparam ROUND = 2'd1;
    localparam FINAL = 2'd2;

    reg [1:0] state;
    reg [1:0] next_state;

    // Internal storage
    reg [DATA_WIDTH-1:0] state_reg;       // Current round state
    reg [DATA_WIDTH-1:0] next_state_reg;  // Next round state
    reg [DATA_WIDTH-1:0] round_key;
    reg [3:0]            round_counter;

    // =============================
    // Simple 4-bit S-box function
    // =============================
    function [3:0] sbox;
        input [3:0] in;
        begin
            case (in)
                4'h0: sbox = 4'he;
                4'h1: sbox = 4'h4;
                4'h2: sbox = 4'hd;
                4'h3: sbox = 4'h1;
                4'h4: sbox = 4'h2;
                4'h5: sbox = 4'hf;
                4'h6: sbox = 4'hb;
                4'h7: sbox = 4'h8;
                4'h8: sbox = 4'h3;
                4'h9: sbox = 4'ha;
                4'ha: sbox = 4'h6;
                4'hb: sbox = 4'hc;
                4'hc: sbox = 4'h5;
                4'hd: sbox = 4'h9;
                4'he: sbox = 4'h0;
                4'hf: sbox = 4'h7;
            endcase
        end
    endfunction

    // =============================
    // Substitution stage
    // =============================
    wire [DATA_WIDTH-1:0] sub_bytes;
    genvar i;
    generate
        for (i = 0; i < DATA_WIDTH/4; i = i + 1) begin : SBOX_STAGE
            assign sub_bytes[i*4 +: 4] = sbox(state_reg[i*4 +: 4]);
        end
    endgenerate

    // =============================
    // Permutation stage (bit rotate)
    // =============================
    wire [DATA_WIDTH-1:0] permuted;
    assign permuted = {sub_bytes[DATA_WIDTH-2:0], sub_bytes[DATA_WIDTH-1]};

    // =============================
    // Round key generation (simple rotation per round)
    // =============================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            round_key <= {DATA_WIDTH{1'b0}};
        else if (state == IDLE && start)
            round_key <= key;
        else if (state == ROUND)
            round_key <= {round_key[DATA_WIDTH-2:0], round_key[DATA_WIDTH-1]};
    end

    // =============================
    // FSM Sequential Logic
    // =============================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            round_counter <= 0;
            state_reg <= 0;
        end else begin
            state <= next_state;

            if (state == IDLE && start) begin
                state_reg <= plaintext;
                round_counter <= 0;
            end
            else if (state == ROUND) begin
                state_reg <= next_state_reg;
                round_counter <= round_counter + 1;
            end
        end
    end

    // =============================
    // FSM Combinational Logic
    // =============================
    always @(*) begin
        next_state = state;
        busy = 1'b0;
        done = 1'b0;
        next_state_reg = state_reg;

        case (state)
            IDLE: begin
                if (start)
                    next_state = ROUND;
            end

            ROUND: begin
                busy = 1'b1;
                next_state_reg = permuted ^ round_key; // AddRoundKey

                if (round_counter == NUM_ROUNDS-1)
                    next_state = FINAL;
            end

            FINAL: begin
                busy = 1'b0;
                done = 1'b1;
                next_state = IDLE;
            end
        endcase
    end

    // =============================
    // Output register
    // =============================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            ciphertext <= 0;
        else if (state == FINAL)
            ciphertext <= state_reg;
    end

    // ==========================================================
    // CWE-1431 VULNERABILITY:
    // Intermediate cryptographic round state exposed externally
    // ==========================================================
    assign debug_state = state_reg;

endmodule
