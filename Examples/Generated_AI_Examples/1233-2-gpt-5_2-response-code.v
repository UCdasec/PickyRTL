module insecure_security_ctrl (
    input  wire        clk,
    input  wire        reset_n,

    // Simple write interface
    input  wire        wr_en,
    input  wire [3:0]  wr_addr,
    input  wire [31:0] wr_data,

    // Security-sensitive output
    output wire        debug_enable
);

    // Security-sensitive control register
    reg [31:0] debug_ctrl_reg;

    // Lock bit register (intended to protect debug_ctrl_reg)
    reg        lock_bit;

    // Address map
    localparam ADDR_DEBUG_CTRL = 4'h0;
    localparam ADDR_LOCK_BIT   = 4'h1;

    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            debug_ctrl_reg <= 32'b0;
            lock_bit       <= 1'b0;
        end else begin
            if (wr_en) begin
                case (wr_addr)
                    ADDR_DEBUG_CTRL: begin
                        // ❌ CWE-1233: Missing lock bit check
                        // This security-sensitive register can be modified
                        // regardless of the lock_bit state
                        debug_ctrl_reg <= wr_data;
                    end

                    ADDR_LOCK_BIT: begin
                        // Lock bit can be set by software
                        lock_bit <= wr_data[0];
                    end

                    default: begin
                        // No operation
                    end
                endcase
            end
        end
    end

    // Debug enable is controlled by bit 0 of the debug control register
    assign debug_enable = debug_ctrl_reg[0];

endmodule
