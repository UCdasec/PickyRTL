// Example of a security-sensitive register block with a CWE-1233 weakness
// NOTE: This module intentionally omits lock-bit enforcement.

module insecure_security_ctrl (
    input  wire        clk,
    input  wire        rst_n,

    // Simple write interface
    input  wire        wr_en,
    input  wire [1:0]  wr_addr,
    input  wire [31:0] wr_data,

    // Outputs
    output reg  [31:0] debug_ctrl,
    output reg         lock_bit
);

    // Address map
    localparam ADDR_DEBUG_CTRL = 2'b00; // Security-sensitive register
    localparam ADDR_LOCK_BIT   = 2'b01; // Lock bit register

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            debug_ctrl <= 32'h00000000;
            lock_bit   <= 1'b0;
        end else begin
            if (wr_en) begin
                case (wr_addr)
                    ADDR_DEBUG_CTRL: begin
                        // SECURITY-SENSITIVE REGISTER WRITE
                        // CWE-1233: Missing lock-bit protection
                        debug_ctrl <= wr_data;
                    end

                    ADDR_LOCK_BIT: begin
                        // Lock bit can be set by software
                        lock_bit <= wr_data[0];
                    end

                    default: begin
                        // No action
                    end
                endcase
            end
        end
    end

endmodule
