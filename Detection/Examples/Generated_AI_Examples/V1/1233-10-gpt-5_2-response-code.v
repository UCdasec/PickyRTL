//-----------------------------------------------------------------------------
// Module: secure_ctrl_block
// Description:
//   Simple memory-mapped control block with a security-sensitive control
//   register and an associated lock bit.
//
//   NOTE: This module intentionally contains a CWE-1233 weakness.
//-----------------------------------------------------------------------------

module secure_ctrl_block (
    input  wire        clk,
    input  wire        rst_n,

    // Simple register interface
    input  wire        write_en,
    input  wire        read_en,
    input  wire [3:0]  addr,
    input  wire [31:0] wdata,
    output reg  [31:0] rdata,

    // Lock bit input (intended to protect the control register)
    input  wire        lock_bit,

    // Security-sensitive output
    output reg         debug_enable
);

    // Security-sensitive configuration register
    reg [31:0] secure_ctrl_reg;

    // Address map
    localparam ADDR_SECURE_CTRL = 4'h0;
    localparam ADDR_STATUS      = 4'h1;

    // Write logic
    always @(posedge clk) begin
        if (!rst_n) begin
            secure_ctrl_reg <= 32'b0;
            debug_enable    <= 1'b0;
        end else if (write_en) begin
            case (addr)
                ADDR_SECURE_CTRL: begin
                    // CWE-1233 WEAKNESS:
                    // The lock_bit is NOT checked here before allowing writes
                    // to a security-sensitive register.
                    secure_ctrl_reg <= wdata;
                    debug_enable    <= wdata[0];
                end
                default: begin
                    // No action
                end
            endcase
        end
    end

    // Read logic
    always @(*) begin
        rdata = 32'b0;
        if (read_en) begin
            case (addr)
                ADDR_SECURE_CTRL: rdata = secure_ctrl_reg;
                ADDR_STATUS:      rdata = {31'b0, lock_bit};
                default:          rdata = 32'b0;
            endcase
        end
    end

endmodule
