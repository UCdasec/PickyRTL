// Description:
// Simple secure session buffer with an intentional CWE-226 weakness.
// A sensitive register retains secret data across session resets
// and is later reused without being cleared.

module insecure_session_buffer (
    input  wire        clk,
    input  wire        rst_n,          // Active-low global reset
    input  wire        session_start,  // Starts a new session
    input  wire        load_secret,    // Load sensitive data
    input  wire [31:0] secret_in,      // Sensitive input data
    input  wire        read_data,       // Read out data
    output reg  [31:0] data_out
);

    // Internal register holding sensitive information
    reg [31:0] secret_reg;

    // Session-active flag
    reg session_active;

    // Sequential logic
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            // Global reset clears session state,
            // but DOES NOT clear the sensitive register
            session_active <= 1'b0;
            data_out       <= 32'b0;
            // secret_reg is intentionally NOT reset here
        end else begin
            // Start of a new session
            if (session_start) begin
                session_active <= 1'b1;
                // secret_reg is reused without clearing
            end

            // Load sensitive data during an active session
            if (session_active && load_secret) begin
                secret_reg <= secret_in;
            end

            // Read path (may expose stale secret data)
            if (read_data) begin
                data_out <= secret_reg;
            end
        end
    end

endmodule
