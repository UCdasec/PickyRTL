module simple_spn_cipher #(
    parameter DATA_WIDTH  = 128,
    parameter KEY_WIDTH   = 128,
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
    output reg  [DATA_WIDTH-1:0]    debug_state  // <-- Vulnerable output
);

    // FSM States
    localparam IDLE  = 2'b00;
    localparam LOAD  = 2'b01;
    localparam ROUND = 2'b10;
    localparam DONE  = 2'b11;

    reg [1:0] state, next_state;

    // Internal registers
    reg [DATA_WIDTH-1:0] state_reg;
    reg [DATA_WIDTH-1:0] round_key;
    reg [2:0]            round_cnt;

    // -----------------------------
    // Simple substitution function
    // -----------------------------
    function [7:0] sbox;
        input [7:0] in;
        begin
            // Simple nonlinear substitution (toy example)
            sbox = {in[6:0], in[7]} ^ 8'hA5;
        end
    endfunction

    // Apply S-box to each byte
    function [DATA_WIDTH-1:0] substitute;
        input [DATA_WIDTH-1:0] data_in;
        integer i;
        begin
            for (i = 0; i < DATA_WIDTH/8; i = i + 1) begin
                substitute[i*8 +: 8] = sbox(data_in[i*8 +: 8]);
            end
        end
    endfunction

    // Simple permutation (bit rotation)
    function [DATA_WIDTH-1:0] permute;
        input [DATA_WIDTH-1:0] data_in;
        begin
            permute = {data_in[DATA_WIDTH-9:0], data_in[DATA_WIDTH-1:DATA_WIDTH-8]};
        end
    endfunction

    // ---------------------------------
    // FSM sequential logic
    // ---------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state      <= IDLE;
            state_reg  <= {DATA_WIDTH{1'b0}};
            round_key  <= {DATA_WIDTH{1'b0}};
            round_cnt  <= 3'd0;
            ciphertext <= {DATA_WIDTH{1'b0}};
            done       <= 1'b0;
            busy       <= 1'b0;
            debug_state<= {DATA_WIDTH{1'b0}};
        end else begin
            state <= next_state;

            case (state)
                IDLE: begin
                    done <= 1'b0;
                    if (start) begin
                        busy <= 1'b1;
                    end
                end

                LOAD: begin
                    state_reg <= plaintext ^ key;  // Initial whitening
                    round_key <= key;
                    round_cnt <= 3'd0;
                end

                ROUND: begin
                    // Round processing
                    state_reg <= permute(substitute(state_reg)) ^ round_key;
                    round_key <= {round_key[KEY_WIDTH-2:0], round_key[KEY_WIDTH-1]}; // Rotate key
                    round_cnt <= round_cnt + 1'b1;

                    // --- CWE-1431 Vulnerability ---
                    // Exposes intermediate round state to external world
                    debug_state <= state_reg;
                end

                DONE: begin
                    ciphertext <= state_reg;
                    done       <= 1'b1;
                    busy       <= 1'b0;
                end
            endcase
        end
    end

    // ---------------------------------
    // FSM combinational logic
    // ---------------------------------
    always @(*) begin
        next_state = state;
        case (state)
            IDLE: begin
                if (start)
                    next_state = LOAD;
            end

            LOAD: begin
                next_state = ROUND;
            end

            ROUND: begin
                if (round_cnt == NUM_ROUNDS - 1)
                    next_state = DONE;
                else
                    next_state = ROUND;
            end

            DONE: begin
                if (!start)
                    next_state = IDLE;
            end
        endcase
    end

endmodule
