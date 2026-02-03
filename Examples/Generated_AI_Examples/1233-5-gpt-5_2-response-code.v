// -----------------------------------------------------------------------------
// Module: secure_ctrl_block
// Description:
//   Simple register block with a security-sensitive control register and
//   an associated lock bit. The design intentionally omits lock checking
//   when writing the secure control register, introducing a CWE-1233 weakness.
// -----------------------------------------------------------------------------

module secure_ctrl_block (
    input  wire        clk,
    input  wire        rst_n,

    // Simple register interface
    input  wire        we,        // write enable
    input  wire [3:0]  addr,      // register address
    input  wire [31:0] wdata,     // write data
    output reg  [31:0] rdata,     // read data

    // Lock bit intended to protect secure_ctrl_reg
    input  wire        lock_bit,

    // Security-sensitive output
    output reg  [31:0] secure_ctrl_out
);

    // Internal registers
    reg [31:0] secure_ctrl_reg;   // security-critical control register
    reg [31:0] status_reg;        // non-sensitive status register

    // Write logic
    always @(posedge clk) begin
        if (!rst_n) begin
            secure_ctrl_reg <= 32'h0000_0000;
            status_reg      <= 32'h0000_0000;
        end else if (we) begin
            case (addr)
                4'h0: begin
                    // CWE-1233 vulnerability:
                    // Missing lock_bit check allows writes even when locked
                    secure_ctrl_reg <= wdata;
                end
                4'h1: begin
                    // Non-sensitive register (no lock required)
                    status_reg <= wdata;
                end
                default: begin
                    // no write
                end
            endcase
        end
    end

    // Read logic
    always @(*) begin
        case (addr)
            4'h0: rdata = secure_ctrl_reg;
            4'h1: rdata = status_reg;
            4'h2: rdata = {31'b0, lock_bit};
            default: rdata = 32'h0000_0000;
        endcase
    end

    // Drive security-sensitive output
    always @(posedge clk) begin
        if (!rst_n) begin
            secure_ctrl_out <= 32'h0000_0000;
        end else begin
            secure_ctrl_out <= secure_ctrl_reg;
        end
    end

endmodule
