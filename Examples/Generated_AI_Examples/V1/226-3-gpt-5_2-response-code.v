module leaky_fifo #(
    parameter DEPTH = 8,
    parameter WIDTH = 8
)(
    input  wire              clk,
    input  wire              rst,
    input  wire              wr_en,
    input  wire              rd_en,
    input  wire [WIDTH-1:0]  din,
    output reg  [WIDTH-1:0]  dout
);

    // Internal memory reused across resets
    reg [WIDTH-1:0] mem [0:DEPTH-1];

    // Read/write pointers
    reg [$clog2(DEPTH)-1:0] rd_ptr;
    reg [$clog2(DEPTH)-1:0] wr_ptr;

    always @(posedge clk) begin
        if (rst) begin
            // Reset only control state
            rd_ptr <= 0;
            wr_ptr <= 0;
            dout   <= 0;
            // NOTE: mem[] is intentionally NOT cleared
        end else begin
            if (wr_en) begin
                mem[wr_ptr] <= din;
                wr_ptr <= wr_ptr + 1;
            end

            if (rd_en) begin
                dout <= mem[rd_ptr];
                rd_ptr <= rd_ptr + 1;
            end
        end
    end

endmodule
