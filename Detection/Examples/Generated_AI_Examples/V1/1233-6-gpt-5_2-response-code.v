// ------------------------------------------------------------
// Module: secure_ctrl_block
// Description:
//   Simple control block with a security-sensitive configuration
//   register and a lock bit. The lock bit exists but is NOT
//   enforced on writes, creating a CWE-1233 vulnerability.
// ------------------------------------------------------------
module secure_ctrl_block (
    input  wire        clk,
    input  wire        rst_n,

    // Simple register interface
    input  wire        wr_en,
    input  wire        rd_en,
    input  wire [3:0]  addr,
    input  wire [31:0] wdata,
    output reg  [31:0] rdata
);

    // --------------------------------------------------------
    // Internal registers
    // --------------------------------------------------------

    // Security-sensitive register controlling privileged behavior
    reg [31:0] secure_cfg_reg;

    // Lock bit intended to protect secure_cfg_reg
    reg        secure_cfg_lock;

    // --------------------------------------------------------
    // Write logic
    // --------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            secure_cfg_reg  <= 32'h0000_0001; // default secure setting
            secure_cfg_lock <= 1'b0;          // unlocked after reset
        end else if (wr_en) begin
            case (addr)
                4'h0: begin
                    // Intended behavior:
                    //   Writes should be blocked when secure_cfg_lock == 1
                    // Vulnerable behavior:
                    //   Lock bit is completely ignored here
                    secure_cfg_reg <= wdata;
                end

                4'h1: begin
                    // Lock register (write-once intended, but not enforced)
                    secure_cfg_lock <= wdata[0];
                end

                default: begin
                    // no-op
                end
            endcase
        end
    end

    // --------------------------------------------------------
    // Read logic
    // --------------------------------------------------------
    always @(*) begin
        rdata = 32'h0000_0000;
        if (rd_en) begin
            case (addr)
                4'h0: rdata = secure_cfg_reg;
                4'h1: rdata = {31'b0, secure_cfg_lock};
                default: rdata = 32'h0000_0000;
            endcase
        end
    end

endmodule
