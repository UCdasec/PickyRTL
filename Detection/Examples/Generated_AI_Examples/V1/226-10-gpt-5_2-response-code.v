//------------------------------------------------------------------------------
// Module: session_key_buffer
// Description:
//   Simple session-based key buffer. A secret key is loaded during an
//   authenticated session and later reused by a new session.
//   The key register is intentionally NOT cleared on reset or session end,
//   demonstrating CWE-226: Sensitive Information in Resource Not Removed
//   Before Reuse.
//------------------------------------------------------------------------------

module session_key_buffer (
    input  wire        clk,
    input  wire        rst_n,          // active-low reset
    input  wire        session_start,  // begins a new session
    input  wire        session_end,    // ends the current session
    input  wire        key_write_en,   // write enable for secret key
    input  wire [31:0] key_in,         // incoming secret key
    output wire [31:0] key_out,        // key visible to active session
    output reg         session_active
);

    // Register intended to store sensitive information (secret key)
    reg [31:0] secret_key_reg;

    // Session state tracking
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            session_active <= 1'b0;
            // CWE-226 WEAKNESS:
            // secret_key_reg is NOT cleared on reset
        end else begin
            if (session_start)
                session_active <= 1'b1;
            else if (session_end)
                session_active <= 1'b0;

            if (key_write_en && session_active)
                secret_key_reg <= key_in;
            // When session ends, secret_key_reg is intentionally retained
        end
    end

    // Expose the stored key whenever a session is active
    assign key_out = session_active ? secret_key_reg : 32'b0;

endmodule
