module simple_spn_cipher #(
    parameter DATA_WIDTH  = 32,
    parameter KEY_WIDTH   = 32,
    parameter NUM_ROUNDS  = 4
)(
    input  wire                     clk,
    input  wire                     rst_n,
    input  wire                     start,
    input  wire [DATA_WIDTH-1:0]    plaintext,
    input  wire [KEY_WIDTH-1:0]     key,
    output reg  [DATA_WIDTH-1:0]    ciphertext,
    output reg                      done,
    output reg                      busy,
    // CWE-1431 weakness: intermediate round state exposed
    output reg  [DATA_WIDTH-1:0]    round_state_out
);

    // FSM states
    localparam IDLE  = 2'd0;
    localparam LOAD  = 2'd1;
    localparam ROUND = 2'd2;
    localparam DONE  = 2'd3;

    reg [1:0] state, next_state;

    // Internal registers
    reg [DATA_WIDTH-1:0] state_reg;
    reg [DATA_WIDTH-1:0] next_state_reg;
    reg [KEY_WIDTH-1:0]  round_key;
    reg [3:0]            round_counter;

    // -----------------------------
    // Simple S-box (4-bit nibble substitution)
    // -----------------------------
    function [3:0] sbox;
        input [3:0] in;
        begin
            case (in)
                4'h0: sbox = 4'hE;
                4'h1: sbox = 4'h4;
                4'h2: sbox = 4'hD;
                4'h3: sbox = 4'h1;
                4'h4: sbox = 4'h2;
                4'h5: sbox = 4'hF;
                4'h6: sbox = 4'hB;
                4'h7: sbox = 4'h8;
                4'h8: sbox = 4'h3;
                4'h9: sbox = 4'hA;
                4'hA: sbox = 4'h6;
                4'hB: sbox = 4'hC;
                4'hC: sbox = 4'h5;
                4'hD: sbox = 4'h9;
                4'hE: sbox = 4'h0;
                4'hF: sbox = 4'h7;
                default: sbox = 4'h0;
            endcase
        end
    endfunction

    // -----------------------------
    // Substitution layer
    // -----------------------------
    function [DATA_WIDTH-1:0] sub_layer;
        input [DATA_WIDTH-1:0] in;
        integer i;
        begin
            for (i = 0; i < DATA_WIDTH/4; i = i + 1) begin
                sub_layer[i*4 +: 4] = sbox(in[i*4 +: 4]);
            end
        end
    endfunction

    // -----------------------------
    // Permutation layer (simple bit rotation)
    // -----------------------------
    function [DATA_WIDTH-1:0] perm_layer;
        input [DATA_WIDTH-1:0] in;
        begin
            perm_layer = {in[DATA_WIDTH-2:0], in[DATA_WIDTH-1]};
        end
    endfunction

    // -----------------------------
    // Round key generation (simple rotation of master key)
    // -----------------------------
    function [KEY_WIDTH-1:0] gen_round_key;
        input [KEY_WIDTH-1:0] master_key;
        input [3:0]           round;
        begin
            gen_round_key = (master_key << round) | (master_key >> (KEY_WIDTH - round));
        end
    endfunction

    // -----------------------------
    // FSM sequential logic
    // -----------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state         <= IDLE;
            state_reg     <= {DATA_WIDTH{1'b0}};
            round_counter <= 4'd0;
            ciphertext    <= {DATA_WIDTH{1'b0}};
            done          <= 1'b0;
            busy          <= 1'b0;
            round_state_out <= {DATA_WIDTH{1'b0}};
        end else begin
            state <= next_state;

            case (state)
                IDLE: begin
                    done <= 1'b0;
                    busy <= 1'b0;
                end

                LOAD: begin
                    state_reg     <= plaintext ^ key; // initial whitening
                    round_counter <= 4'd0;
                    busy          <= 1'b1;
                end

                ROUND: begin
                    state_reg     <= next_state_reg;
                    round_counter <= round_counter + 1;
                end

                DONE: begin
                    ciphertext <= state_reg;
                    done       <= 1'b1;
                    busy       <= 1'b0;
                end
            endcase

            // CWE-1431 weakness:
            // Intermediate cryptographic state is continuously driven to output
            round_state_out <= state_reg;
        end
    end

    // -----------------------------
    // FSM combinational logic
    // -----------------------------
    always @(*) begin
        next_state = state;
        next_state_reg = state_reg;
        round_key = gen_round_key(key, round_counter);

        case (state)
            IDLE: begin
                if (start)
                    next_state = LOAD;
            end

            LOAD: begin
                next_state = ROUND;
            end

            ROUND: begin
                // Round processing:
                // 1. Substitution
                // 2. Permutation
                // 3. Add round key
                next_state_reg = perm_layer(sub_layer(state_reg)) ^ round_key;

                if (round_counter == NUM_ROUNDS - 1)
                    next_state = DONE;
            end

            DONE: begin
                if (!start)
                    next_state = IDLE;
            end
        endcase
    end

endmodule
