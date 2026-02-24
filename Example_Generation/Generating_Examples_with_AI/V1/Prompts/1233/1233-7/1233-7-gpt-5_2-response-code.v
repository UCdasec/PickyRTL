module insecure_debug_control (
    input  wire        clk,
    input  wire        reset_n,

    // Simple write interface
    input  wire        write_en,
    input  wire [1:0]  write_addr,
    input  wire [31:0] write_data,

    // Security-sensitive output
    output wire        debug_mode_en
);

    // Security-sensitive register controlling debug access
    reg debug_enable_reg;

    // Lock bit intended to prevent further modification
    reg lock_bit;

    // Address map
    localparam ADDR_DEBUG_ENABLE = 2'b00;
    localparam ADDR_LOCK         = 2'b01;

    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            debug_enable_reg <= 1'b0;
            lock_bit         <= 1'b0;
        end else begin
            if (write_en) begin
                case (write_addr)
                    ADDR_DEBUG_ENABLE: begin
                        // CWE-1233 VULNERABILITY:
                        // Missing lock_bit check allows modification
                        // even after the register is supposedly locked
                        debug_enable_reg <= write_data[0];
                    end

                    ADDR_LOCK: begin
                        // Lock bit can be set
                        lock_bit <= write_data[0];
                    end

                    default: begin
                        // No action
                    end
                endcase
            end
        end
    end

    assign debug_mode_en = debug_enable_reg;

endmodule
