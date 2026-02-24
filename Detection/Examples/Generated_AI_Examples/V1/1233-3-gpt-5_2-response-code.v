module secure_control_block (
    input  wire        clk,
    input  wire        rst_n,

    // Simple bus interface
    input  wire        bus_we,
    input  wire [3:0]  bus_addr,
    input  wire [31:0] bus_wdata,
    output reg  [31:0] bus_rdata,

    // Debug interface (intended for manufacturing)
    input  wire        dbg_we,
    input  wire [31:0] dbg_wdata
);

    // Address map
    localparam ADDR_SECURE_CFG = 4'h0;
    localparam ADDR_LOCK      = 4'h1;

    // Security-sensitive configuration register
    // Controls privileged system behavior
    reg [31:0] secure_cfg_reg;

    // Lock bit intended to prevent further modification
    reg        lock_bit;

    // Write logic
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            secure_cfg_reg <= 32'h0000_0000;
            lock_bit       <= 1'b0;
        end else begin
            // Normal bus writes
            if (bus_we) begin
                case (bus_addr)
                    ADDR_SECURE_CFG: begin
                        // Intended: should block writes when lock_bit == 1
                        // Actual: lock_bit is NOT checked
                        secure_cfg_reg <= bus_wdata;
                    end

                    ADDR_LOCK: begin
                        // Lock bit can be set once
                        lock_bit <= 1'b1;
                    end
                endcase
            end

            // Debug write path (higher priority, bypasses lock intent)
            if (dbg_we) begin
                // Direct write to security-sensitive register
                // No lock bit enforcement
                secure_cfg_reg <= dbg_wdata;
            end
        end
    end

    // Read logic
    always @(*) begin
        case (bus_addr)
            ADDR_SECURE_CFG: bus_rdata = secure_cfg_reg;
            ADDR_LOCK:       bus_rdata = {31'b0, lock_bit};
            default:         bus_rdata = 32'h0000_0000;
        endcase
    end

endmodule
