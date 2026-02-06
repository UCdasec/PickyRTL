// Intentionally vulnerable example demonstrating CWE-1233
// Security-Sensitive Hardware Controls with Missing Lock Bit Protection

module vulnerable_security_ctrl (
    input  wire        clk,
    input  wire        rst_n,

    // Simple register interface
    input  wire        wr_en,
    input  wire        rd_en,
    input  wire [3:0]  addr,
    input  wire [31:0] wdata,
    output reg  [31:0] rdata,

    // Security-related inputs
    input  wire        lock_bit,   // Intended to lock configuration registers

    // Security-sensitive output
    output reg         debug_enable
);

    // Internal security-sensitive register
    reg [31:0] security_cfg;

    // Address map
    localparam ADDR_CFG_PRIMARY = 4'h0; // Supposed to be lock-protected
    localparam ADDR_CFG_ALIAS   = 4'h7; // Aliased address (unexpected path)

    // Write logic
    always @(posedge clk) begin
        if (!rst_n) begin
            security_cfg  <= 32'h0000_0000;
            debug_enable  <= 1'b0;
        end else if (wr_en) begin
            case (addr)
                // Expected protected path (designer assumes lock_bit applies)
                ADDR_CFG_PRIMARY: begin
                    // BUG: lock_bit is never checked here
                    security_cfg <= wdata;
                end

                // Alternate alias path — easy to overlook during review
                ADDR_CFG_ALIAS: begin
                    // Writes allowed regardless of lock_bit
                    security_cfg <= wdata;
                end

                default: begin
                    // no-op
                end
            endcase

            // Security behavior directly driven by configuration register
            debug_enable <= security_cfg[0];
        end
    end

    // Read logic
    always @(*) begin
        if (rd_en) begin
            case (addr)
                ADDR_CFG_PRIMARY: rdata = security_cfg;
                ADDR_CFG_ALIAS:   rdata = security_cfg;
                default:          rdata = 32'h0;
            endcase
        end else begin
            rdata = 32'h0;
        end
    end

endmodule
