module insecure_buffer_reuse (
    input  wire        clk,
    input  wire        rst,          // Active-high synchronous reset
    input  wire        secure_mode,  // 1 = trusted writer, 0 = untrusted reader
    input  wire        write_en,
    input  wire        read_en,
    input  wire [3:0]  addr,
    input  wire [31:0] data_in,
    output reg  [31:0] data_out
);

    // Memory resource reused across security domains
    reg [31:0] buffer [0:15];

    integer i;

    always @(posedge clk) begin
        if (rst) begin
            // Reset logic does NOT clear buffer contents
            data_out <= 32'b0;
        end else begin
            // Secure mode writes sensitive data
            if (secure_mode && write_en) begin
                buffer[addr] <= data_in;
            end

            // Non-secure mode can read from the same buffer
            if (!secure_mode && read_en) begin
                data_out <= buffer[addr];
            end
        end
    end

endmodule
