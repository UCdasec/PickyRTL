// Description:
// Simple session-based key storage module.
// A secret key is loaded during an active session and can be read out.
// When a session ends, the storage resource is reused without clearing
// the sensitive data (intentional CWE-226 weakness).

module session_key_store (
    input  wire        clk,
    input  wire        rst_n,

    // Session control
    input  wire        start_session,
    input  wire        end_session,

    // Key handling
    input  wire        load_key,
    input  wire [127:0] key_in,

    // Data output
    input  wire        read_key,
    output reg  [127:0] key_out
);

    // Indicates whether a session is currently active
    reg session_active;

    // Sensitive resource: stores a secret key
    reg [127:0] key_buffer;

    // Session and key management
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            session_active <= 1'b0;
            key_out        <= 128'b0;
            // NOTE: key_buffer is NOT cleared here intentionally
        end else begin
            if (start_session) begin
                session_active <= 1'b1;
            end

            if (end_session) begin
                session_active <= 1'b0;
                // key_buffer is intentionally retained
            end

            if (session_active && load_key) begin
                key_buffer <= key_in;
            end

            if (read_key) begin
                key_out <= key_buffer;
            end
        end
    end

endmodule
