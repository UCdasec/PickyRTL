//------------------------------------------------------------------------------
// Module: insecure_buffer
// Description:
//   Demonstrates CWE-226 by retaining sensitive data in a reusable register
//   across reset and privilege mode changes.
//------------------------------------------------------------------------------

module insecure_buffer (
    input  wire        clk,
    input  wire        rst_n,        // Active-low reset
    input  wire        priv_mode,    // 1 = privileged, 0 = unprivileged
    input  wire        write_en,
    input  wire        read_en,
    input  wire [31:0] data_in,
    output reg  [31:0] data_out
);

    // This register is intended to store sensitive information
    // (e.g., a cryptographic key or password)
    reg [31:0] shared_reg;

    // Write logic
    always @(posedge clk) begin
        if (!rst_n) begin
            // CWE-226 weakness:
            // shared_reg is NOT cleared on reset and retains old sensitive data
            data_out <= 32'b0;
        end else begin
            // Only privileged mode is allowed to write sensitive data
            if (priv_mode && write_en) begin
                shared_reg <= data_in;
            end

            // Any mode can read the register
            if (read_en) begin
                data_out <= shared_reg;
            end
        end
    end

endmodule
