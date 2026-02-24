module crypto_core_with_leakage
(
    input clk,
    input rst,
    input [127:0] data_i,
    output [127:0] data_o,
    output valid
);

localparam int total_rounds = 10;
logic [3:0] round_id_q;
logic [127:0] data_state_q, data_state_d;
logic [127:0] key_state_q, key_state_d;

crypto_algo_round u_algo_round (
    .clk (clk),
    .rst (rst),
    .round_i (round_id_q ),
    .key_i (key_state_q ),
    .data_i (data_state_q),
    .key_o (key_state_d ),
    .data_o (data_state_d)
);

always @(posedge clk) begin
    if (rst) 
    begin
        data_state_q <= 0;
        key_state_q <= 0;
        round_id_q <= 0;
    end
    else 
    begin
        case (round_id_q)
        total_rounds: 
        begin
            data_state_q <= 0;
            key_state_q <= 0;
            round_id_q <= 0;
        end
        default: 
        begin
            data_state_q <= data_state_d;
            key_state_q <= key_state_d;
            round_id_q <= round_id_q + 1;
        end
        endcase
    end
end //always @(posedge clk)

assign valid = (round_id_q == total_rounds) ? 1'b1 : 1'b0;
assign data_o = data_state_q;
endmodule