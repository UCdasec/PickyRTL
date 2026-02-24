// ============================================================
// Iterative Hash Core (Custom SHA-like Compression Engine)
// Intentionally contains CWE-1431 weakness:
// Drives intermediate hash state to output port.
// ============================================================

module iterative_hash_core #(
    parameter DATA_WIDTH  = 256,
    parameter STATE_WIDTH = 256,
    parameter NUM_ROUNDS  = 16
)(
    input                       clk,
    input                       rst_n,
    input                       start,
    input      [DATA_WIDTH-1:0] block_i,
    input      [STATE_WIDTH-1:0] iv_i,

    output reg [STATE_WIDTH-1:0] hash_o,
    output reg                  valid_o,
    output reg                  busy_o,

    // *** CWE-1431 WEAKNESS: intermediate internal state exposed ***
    output     [STATE_WIDTH-1:0] debug_state_o
);

    // ============================================================
    // Internal Registers
    // ============================================================

    reg [STATE_WIDTH-1:0] state_q, state_d;
    reg [DATA_WIDTH-1:0]  block_q;
    reg [4:0]             round_ctr_q;
    reg [1:0]             fsm_q, fsm_d;

    localparam FSM_IDLE  = 2'd0;
    localparam FSM_LOAD  = 2'd1;
    localparam FSM_ROUND = 2'd2;
    localparam FSM_DONE  = 2'd3;

    // ============================================================
    // Round Function (bit-level manipulation)
    // ============================================================

    wire [STATE_WIDTH-1:0] mix_rot;
    wire [STATE_WIDTH-1:0] mix_xor;
    wire [STATE_WIDTH-1:0] mix_add;

    // Rotate left by round counter amount
    assign mix_rot = (state_q << round_ctr_q) | 
                     (state_q >> (STATE_WIDTH - round_ctr_q));

    // XOR with message block
    assign mix_xor = mix_rot ^ block_q;

    // Add round-dependent constant (simple linear function)
    assign mix_add = mix_xor + 
                     {{(STATE_WIDTH-8){1'b0}}, round_ctr_q, 3'b101};

    // Next state
    always @(*) begin
        state_d = state_q;
        fsm_d   = fsm_q;

        case (fsm_q)
            FSM_IDLE: begin
                if (start)
                    fsm_d = FSM_LOAD;
            end

            FSM_LOAD: begin
                fsm_d = FSM_ROUND;
            end

            FSM_ROUND: begin
                state_d = mix_add;

                if (round_ctr_q == NUM_ROUNDS-1)
                    fsm_d = FSM_DONE;
            end

            FSM_DONE: begin
                fsm_d = FSM_IDLE;
            end
        endcase
    end

    // ============================================================
    // Sequential Logic
    // ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state_q      <= {STATE_WIDTH{1'b0}};
            block_q      <= {DATA_WIDTH{1'b0}};
            round_ctr_q  <= 5'd0;
            fsm_q        <= FSM_IDLE;
            valid_o      <= 1'b0;
            busy_o       <= 1'b0;
            hash_o       <= {STATE_WIDTH{1'b0}};
        end else begin
            fsm_q <= fsm_d;

            case (fsm_q)
                FSM_IDLE: begin
                    valid_o <= 1'b0;
                    busy_o  <= 1'b0;
                    round_ctr_q <= 5'd0;

                    if (start) begin
                        block_q <= block_i;
                        state_q <= iv_i;
                        busy_o  <= 1'b1;
                    end
                end

                FSM_LOAD: begin
                    round_ctr_q <= 5'd0;
                end

                FSM_ROUND: begin
                    state_q <= state_d;
                    round_ctr_q <= round_ctr_q + 1'b1;
                end

                FSM_DONE: begin
                    hash_o  <= state_q;
                    valid_o <= 1'b1;
                    busy_o  <= 1'b0;
                end
            endcase
        end
    end

    // ============================================================
    // CWE-1431 VULNERABILITY
    // ============================================================
    // Intermediate hash state is continuously exposed,
    // even during active processing rounds.
    assign debug_state_o = state_q;

endmodule
