// Description:
// Simple security control block with a configuration register and lock bit.
// This module intentionally contains a CWE-1233 weakness: writes to a
// security-sensitive register are allowed even when the lock bit is set.

module security_ctrl (
    input  wire        clk,
    input  wire        rst_n,

    // Simple register write interface
    input  wire        wr_en,
    input  wire [1:0]  addr,
    input  wire [31:0] wr_data,

    // Outputs
    output reg  [31:0] sec_cfg_o,   // Security-sensitive configuration
    output reg         debug_en_o   // Derived security behavior
);

    // Register map
    // addr = 0x0 : sec_cfg register (security-sensitive)
    // addr = 0x1 : lock register (bit[0] = lock)

    reg        lock_bit;

    // Write logic
    always @(posedge clk) begin
        if (!rst_n) begin
            sec_cfg_o <= 32'h0000_0000;
            lock_bit  <= 1'b0;
        end else if (wr_en) begin
            case (addr)
                2'b00: begin
                    // CWE-1233 WEAKNESS:
                    // sec_cfg_o is security-sensitive, but the lock_bit
                    // is NOT checked before allowing the write.
                    sec_cfg_o <= wr_data;
                end

                2'b01: begin
                    // Lock bit can be set by software
                    lock_bit <= wr_data[0];
                end

                default: begin
                    // no-op
                end
            endcase
        end
    end

    // Security-relevant behavior derived from sec_cfg_o
    always @(*) begin
        // Example: bit[0] enables debug access
        debug_en_o = sec_cfg_o[0];
    end

endmodule
