
module otp_ctrl_scrmbl(
    input clk_i,
    input rst_ni,
    output logic data_o,
    output logic valid_o,
    output logic ready_o
);

logic valid;
logic scramble_finished;
logic scrambled_data;

always @(posedge clk_i) begin
    if (!rst_ni) begin
        data_o <= '0;
        valid_o <= 1'b0;
        ready_o <= 1'b1;
    end else begin
        if (scramble_finished) begin
            valid <= 1'b1;
        end else begin
            valid <= 1'b0;
        end
    end
end

assign valid_o = valid;
assign data_o = (valid_o) ? scrambled_data : 0;

scramble scramble(
    .clk(clk_i),
    .rst(rst_ni),
    .scrambled_data(scrambled_data),
    .finished(scramble_finished)
);

endmodule