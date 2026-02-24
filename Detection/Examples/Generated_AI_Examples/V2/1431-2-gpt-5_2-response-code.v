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
    // CWE-1431: Intermediate round state exposed externally
    output reg  [DATA_WIDTH-1:0]    round_state_out
);

    // FSM states
    localparam IDLE    = 2'd0;
    localparam PROCESS = 2'd1;
    localparam FINISH  = 2'd2;

    reg [1:0] state, next_state;

    // Internal registers
    reg [DATA_WIDTH-1:0] state_reg;
    reg [DATA_WIDTH-1:0] next_state_reg;
    reg [KEY_WIDTH-1:0]  round_key;
    reg [2:0]            round_counter;

    // ----------------------------
    // Simple S-box (4-bit nibble substitution)
    // ----------------------------
    function [3:0] sbox;
        input [3:0] in;
        begin
            case (in)
                4'h0: sbox = 4'hC;
                4'h1: sbox = 4'h5;
                4'h2: sbox = 4'h6;
                4'h3: sbox = 4'hB;
                4'h4: sbox = 4'h9;
                4'h5: sbox = 4'h0;
                4'h6: sbox = 4'hA;
                4'h7: sbox = 4'hD;
                4'h8: sbox = 4'h3;
                4'h9: sbox = 4'hE;
                4'hA: sbox = 4'hF;
                4'hB: sbox = 4'h8;
                4'hC: sbox = 4'h4;
                4'hD: sbox = 4'h7;
                4'hE: sbox = 4'h1;
                4'hF: sbox = 4'h2;
            endcase
        end
    endfunction

    // ----------------------------
    // Substitution Layer
    // ----------------------------
    function [DATA_WIDTH-1:0] substitute;
        input [DATA_WIDTH-1:0] data_in;
        integer i;
        begin
            for (i = 0; i < DATA_WIDTH/4; i = i + 1) begin
                substitute[i*4 +: 4] = sbox(data_in[i*4 +: 4]);
            end
        end
    endfunction

    // ----------------------------
    // Permutation Layer (simple rotation)
    // ----------------------------
    function [DATA_WIDTH-1:0] permute;
        input [DATA_WIDTH-1:0] data_in;
        begin
            permute = {data_in[DATA_WIDTH-5:0], data_in[DATA_WIDTH-1:DATA_WIDTH-4]};
        end
    endfunction

    // ----------------------------
    // Round Key Generation (simple rotation per round)
    // ----------------------------
    always @(*) begin
        round_key = {key[KEY_WIDTH-1-round_counter:0], 
                     key[KEY_WIDTH-1:KEY_WIDTH-round_counter]};
    end

    // ----------------------------
    // FSM Next-State Logic
    // ----------------------------
    always @(*) begin
        next_state = state;
        case (state)
            IDLE: begin
                if (start)
                    next_state = PROCESS;
            end
            PROCESS: begin
                if (round_counter == NUM_ROUNDS)
                    next_state = FINISH;
            end
            FINISH: begin
                next_state = IDLE;
            end
        endcase
    end

    // ----------------------------
    // Sequential Logic
    // ----------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state            <= IDLE;
            state_reg        <= {DATA_WIDTH{1'b0}};
            ciphertext       <= {DATA_WIDTH{1'b0}};
            done             <= 1'b0;
            busy             <= 1'b0;
            round_counter    <= 3'd0;
            round_state_out  <= {DATA_WIDTH{1'b0}};
        end else begin
            state <= next_state;

            case (state)
                IDLE: begin
                    done          <= 1'b0;
                    busy          <= 1'b0;
                    round_counter <= 3'd0;
                    if (start) begin
                        state_reg <= plaintext;
                        busy      <= 1'b1;
                    end
                end

                PROCESS: begin
                    busy <= 1'b1;

                    // Multi-stage round processing
                    next_state_reg = state_reg ^ round_key;          // AddRoundKey
                    next_state_reg = substitute(next_state_reg);     // SubBytes
                    next_state_reg = permute(next_state_reg);        // Permute

                    state_reg <= next_state_reg;

                    // CWE-1431: Driving intermediate round state externally
                    round_state_out <= next_state_reg;

                    round_counter <= round_counter + 1'b1;
                end

                FINISH: begin
                    ciphertext <= state_reg;
                    done       <= 1'b1;
                    busy       <= 1'b0;
                end
            endcase
        end
    end

endmodule
