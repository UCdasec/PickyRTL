// Description:
// Simple secure buffer that stores a sensitive value for a session.
// Intentionally vulnerable: sensitive data is not cleared before reuse.

module insecure_session_buffer (
    input  wire        clk,
    input  wire        rst_n,

    // Control signals
    input  wire        session_start,
    input  wire        session_end,

    // Data interface
    input  wire        write_en,
    input  wire [31:0] secret_in,
    input  wire        read_en,
    output reg  [31:0] data_out
);

    // Internal register holding sensitive information
    reg [31:0] secret_reg;

    // Session active flag
    reg session_active;

    // Session control logic
    always @(posedge clk) begin
        if (!rst_n) begin
            session_active <= 1'b0;
            // NOTE: secret_reg is intentionally NOT cleared on reset
        end else begin
            if (session_start)
                session_active <= 1'b1;
            else if (session_end)
                session_active <= 1'b0;
        end
    end

    // Write sensitive data during an active session
    always @(posedge clk) begin
        if (session_active && write_en) begin
            secret_reg <= secret_in;
        end
        // NOTE: secret_reg is NOT cleared when session ends
    end

    // Read path
    always @(*) begin
        if (read_en)
            data_out = secret_reg;
        else
            data_out = 32'b0;
    end

endmodule
