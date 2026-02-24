module simple_spn_cipher_with_leakage #
(
    parameter DATA_WIDTH  = 128,
    parameter KEY_WIDTH   = 128,
    parameter NUM_ROUNDS  = 8
)
(
    input                       clk,
    input                       rst,
    input                       start,
    input      [DATA_WIDTH-1:0] plaintext_i,
    input      [KEY_WIDTH-1:0]  key_i,
    output reg [DATA_WIDTH-1:0] ciphertext_o,
    output                      valid_o,
    output                      busy_o,
    // CWE-1431: Intermediate state exposed
    output     [DATA_WIDTH-1:0] round_state_o
);

    //========================================================
    // FSM State Encoding
    //========================================================
    localparam IDLE = 2'b00;
    localparam LOAD = 2'b01;
    localparam RUN  = 2'b10;
    localparam DONE = 2'b11;

    reg [1:0] state_q, state_d;

    //========================================================
    // Internal Registers
    //========================================================
    reg [DATA_WIDTH-1:0] state_q_reg, state_d_reg;
    reg [KEY_WIDTH-1:0]  key_q_reg;
    reg [$clog2(NUM_ROUNDS+1)-1:0] round_cnt_q, round_cnt_d;

    //========================================================
    // Simple Substitution Function (Nibble-wise inversion)
    //========================================================
    function [DATA_WIDTH-1:0] sub_bytes;
        input [DATA_WIDTH-1:0] data_in;
        integer i;
        reg [DATA_WIDTH-1:0] tmp;
        begin
            for (i = 0; i < DATA_WIDTH; i = i + 4) begin
                tmp[i +: 4] = ~data_in[i +: 4]; // simple invert S-box
            end
            sub_bytes = tmp;
        end
    endfunction

    //========================================================
    // Permutation (Rotate left by round index)
    //========================================================
    function [DATA_WIDTH-1:0] permute;
        input [DATA_WIDTH-1:0] data_in;
        input [$clog2(NUM_ROUNDS+1)-1:0] round;
        begin
            permute = (data_in << round) | (data_in >> (DATA_WIDTH - round));
        end
    endfunction

    //========================================================
    // Combinational Next-State Logic
    //========================================================
    always @(*) begin
        state_d      = state_q;
        state_d_reg  = state_q_reg;
        round_cnt_d  = round_cnt_q;

        case (state_q)
            IDLE: begin
                if (start)
                    state_d = LOAD;
            end

            LOAD: begin
                state_d_reg = plaintext_i ^ key_i; // initial whitening
                round_cnt_d = 0;
                state_d     = RUN;
            end

            RUN: begin
                // Round transformation: Substitution + Permutation + Key mixing
                state_d_reg = permute(sub_bytes(state_q_reg), round_cnt_q)
                              ^ key_q_reg;

                if (round_cnt_q == NUM_ROUNDS-1)
                    state_d = DONE;

                round_cnt_d = round_cnt_q + 1;
            end

            DONE: begin
                state_d = IDLE;
            end

            default: state_d = IDLE;
        endcase
    end

    //========================================================
    // Sequential Logic
    //========================================================
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            state_q      <= IDLE;
            state_q_reg  <= {DATA_WIDTH{1'b0}};
            key_q_reg    <= {KEY_WIDTH{1'b0}};
            round_cnt_q  <= 0;
            ciphertext_o <= {DATA_WIDTH{1'b0}};
        end else begin
            state_q      <= state_d;
            state_q_reg  <= state_d_reg;
            round_cnt_q  <= round_cnt_d;

            if (state_q == LOAD)
                key_q_reg <= key_i;

            if (state_q == DONE)
                ciphertext_o <= state_q_reg;
        end
    end

    //========================================================
    // Status Signals
    //========================================================
    assign busy_o  = (state_q == RUN);
    assign valid_o = (state_q == DONE);

    //========================================================
    // CWE-1431 Vulnerability:
    // Intermediate cryptographic state is directly exposed
    //========================================================
    assign round_state_o = state_q_reg;

endmodule
