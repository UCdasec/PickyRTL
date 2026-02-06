// -----------------------------------------------------------------------------
// Module: secure_ctrl_reg
//
// Description:
//   Simple memory-mapped control register intended to hold a security-critical
//   configuration value (e.g., debug enable or privilege control).
//
//   A lock bit input is provided but is NOT enforced when writing the register.
//   This intentionally introduces a CWE-1233 weakness.
// -----------------------------------------------------------------------------

module secure_ctrl_reg (
    input  wire        clk,
    input  wire        rst_n,

    // Simple write interface
    input  wire        write_en,
    input  wire [31:0] write_data,

    // Security lock bit (intended to protect ctrl_reg)
    input  wire        lock_bit,

    // Outputs
    output reg  [31:0] ctrl_reg,
    output wire        debug_enable
);

    // ctrl_reg[0] is assumed to enable a privileged debug feature
    assign debug_enable = ctrl_reg[0];

    // Write logic
    always @(posedge clk) begin
        if (!rst_n) begin
            ctrl_reg <= 32'h0000_0000;
        end
        else if (write_en) begin
            // -------------------------------------------------------------
            // CWE-1233 VULNERABILITY:
            // The lock_bit is NOT checked here. Even when lock_bit == 1,
            // ctrl_reg can still be modified.
            // -------------------------------------------------------------
            ctrl_reg <= write_data;
        end
    end

endmodule
