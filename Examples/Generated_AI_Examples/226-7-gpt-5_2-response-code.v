module insecure_key_buffer (
    input  wire        clk,
    input  wire        reset_n,      // Active-low reset
    input  wire        secure_mode,   // 1 = load secret, 0 = normal operation
    input  wire [31:0] data_in,
    output reg  [31:0] data_out
);

    // This register is used to store sensitive data (e.g., a secret key)
    // and later reused as a general-purpose buffer.
    reg [31:0] buffer_reg;

    always @(posedge clk) begin
        if (!reset_n) begin
            // INTENTIONAL WEAKNESS:
            // buffer_reg is NOT cleared on reset.
            // data_out is cleared, but the sensitive buffer is retained.
            data_out <= 32'b0;
        end else begin
            if (secure_mode) begin
                // In secure mode, load sensitive information
                buffer_reg <= data_in;     // e.g., cryptographic key
                data_out   <= 32'b0;
            end else begin
                // In normal mode, the same register is reused
                // without clearing its previous sensitive contents.
                data_out   <= buffer_reg;  // Leaks old sensitive data
                buffer_reg <= data_in;     // Reused as a normal buffer
            end
        end
    end

endmodule
