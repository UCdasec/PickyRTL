// -----------------------------------------------------------------------------
// Module: session_buffer
// Description:
//   Simple session-based data buffer that stores a "secret" value during a
//   privileged session and later reuses the same register during an
//   unprivileged session without clearing it.
// -----------------------------------------------------------------------------

module session_buffer (
    input  wire        clk,
    input  wire        rst_n,

    input  wire        session_start,   // starts a new session
    input  wire        privileged_mode, // 1 = privileged, 0 = unprivileged
    input  wire        write_en,
    input  wire [31:0] data_in,

    output reg  [31:0] data_out
);

    // Internal register that may hold sensitive information
    reg [31:0] session_reg;

    // Session register logic
    always @(posedge clk) begin
        if (!rst_n) begin
            // CWE-226 weakness:
            // session_reg is NOT cleared on reset
            data_out <= 32'b0;
        end else begin
            if (session_start) begin
                // New session begins, but old data is retained
                // CWE-226: sensitive data is not removed before reuse
                data_out <= session_reg;
            end

            if (write_en) begin
                if (privileged_mode) begin
                    // Privileged software writes sensitive data
                    session_reg <= data_in;
                end else begin
                    // Unprivileged software can still influence output,
                    // but does not overwrite the old sensitive value
                    data_out <= session_reg;
                end
            end
        end
    end

endmodule
