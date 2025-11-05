module example_1 (
    input clk,
    input reset,
    input [7:0] data_input,
    input lock_sys_config,
    outout reg [7:0] sys_config_output
);

    reg [7:0] sys_config_reg

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            sys_config_reg <= 8'h00;
        end else begin
            sys_config_reg <= data_input
        end
    end
endmodule