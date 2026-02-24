module spn_cipher_core #(
    parameter DATA_WIDTH = 128,
    parameter NUM_ROUNDS = 4
)(
    input                   clk,
    input                   rst_n,
    input                   start,
    input  [DATA_WIDTH-1:0] plaintext,
    input  [DATA_WIDTH-1:0] key,
    output reg [DATA_WIDTH-1:0] ciphertext,
    output reg                  busy,
    output reg                  done,
    output reg [DATA_WIDTH-1:0] intermediate_state_out  // <-- Exposes internal state (CWE-1431)
);

    // FSM state encoding
    localparam IDLE  = 2'b00;
    localparam ROUND = 2'b01;
    localparam DONE  = 2'b10;

    reg [1:0] state, next_state;

    // Internal registers
    reg [DATA_WIDTH-1:0] state_reg;
    reg [DATA_WIDTH-1:0] round_key;
    reg [$clog2(NUM_ROUNDS+1)-1:0] round_counter;

    wire [DATA_WIDTH-1:0] substituted;
    wire [DATA_WIDTH-1:0] permuted;
    wire [DATA_WIDTH-1:0] next_state_value;

    // Simple substitution layer (bitwise inversion as placeholder S-box)
    assign substituted = ~state_reg;

    // Simple permutation layer (rotate left by 8 bits)
    assign permuted = {substituted[DATA_WIDTH-9:0], substituted[DATA_WIDTH-1:DATA_WIDTH-8]};

    // Round transformation: XOR with key
    assign next_state_value = permuted ^ round_key;

    // Round key derivation (simple rotation per round)
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            round_key <= {DATA_WIDTH{1'b0}};
        else if (state == IDLE && start)
            round_key <= key;
        else if (state == ROUND)
            round_key <= {round_key[DATA_WIDTH-2:0], round_key[DATA_WIDTH-1]};
    end

    // FSM sequential logic
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            state <= IDLE;
        else
            state <= next_state;
    end

    // FSM combinational logic
    always @(*) begin
        case (state)
            IDLE: begin
                if (start)
                    next_state = ROUND;
                else
                    next_state = IDLE;
            end
            ROUND: begin
                if (round_counter == NUM_ROUNDS)
                    next_state = DONE;
                else
                    next_state = ROUND;
            end
            DONE: begin
                next_state = IDLE;
            end
            default: next_state = IDLE;
        endcase
    end

    // Round counter and state register update
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state_reg     <= {DATA_WIDTH{1'b0}};
            round_counter <= 0;
        end else begin
            case (state)
                IDLE: begin
                    if (start) begin
                        state_reg     <= plaintext;
                        round_counter <= 0;
                    end
                end
                ROUND: begin
                    state_reg     <= next_state_value;
                    round_counter <= round_counter + 1;
                end
                DONE: begin
                    state_reg     <= state_reg;
                    round_counter <= 0;
                end
            endcase
        end
    end

    // Output logic
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            ciphertext              <= {DATA_WIDTH{1'b0}};
            busy                    <= 1'b0;
            done                    <= 1'b0;
            intermediate_state_out  <= {DATA_WIDTH{1'b0}};
        end else begin
            case (state)
                IDLE: begin
                    busy <= 1'b0;
                    done <= 1'b0;
                end
                ROUND: begin
                    busy <= 1'b1;
                    done <= 1'b0;
                end
                DONE: begin
                    ciphertext <= state_reg;
                    busy       <= 1'b0;
                    done       <= 1'b1;
                end
            endcase

            // CWE-1431: Driving intermediate cryptographic state to output
            intermediate_state_out <= state_reg;
        end
    end

endmodule
