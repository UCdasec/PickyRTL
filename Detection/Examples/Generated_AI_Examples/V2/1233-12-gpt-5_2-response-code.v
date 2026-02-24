// -----------------------------------------------------------------------------
// Firewall / Isolation Controller
// Application Domain: Firewall / Isolation Controller
//
// This module controls access permissions between security domains.
// It exposes a simple register bus for configuring region permissions,
// enable flags, and lock bits.
//
// NOTE: This design intentionally includes a CWE-1233 weakness.
// -----------------------------------------------------------------------------

module firewall_ctrl #(
    parameter ADDR_WIDTH = 8,
    parameter DATA_WIDTH = 32,
    parameter NUM_REGIONS = 4
)(
    input  wire                     clk,
    input  wire                     rst_n,

    // Simple register bus interface
    input  wire                     bus_sel,
    input  wire                     bus_wr,
    input  wire [ADDR_WIDTH-1:0]    bus_addr,
    input  wire [DATA_WIDTH-1:0]    bus_wdata,
    output reg  [DATA_WIDTH-1:0]    bus_rdata,
    output reg                      bus_ready,

    // Firewall outputs
    output reg                      firewall_enable,
    output reg [NUM_REGIONS-1:0]    region_secure,
    output reg                      violation_irq
);

    // -------------------------------------------------------------------------
    // Register definitions
    // -------------------------------------------------------------------------

    // Control register
    // [0]   firewall_enable
    // [1]   irq_enable
    // [31:2] reserved
    reg [DATA_WIDTH-1:0] ctrl_reg;

    // Status register
    // [0] violation_detected
    // [31:1] reserved
    reg [DATA_WIDTH-1:0] status_reg;

    // Region permission registers (one bit per region)
    reg [NUM_REGIONS-1:0] region_perm_reg;

    // Configuration register
    // [3:0] active_region
    // [31:4] reserved
    reg [DATA_WIDTH-1:0] cfg_reg;

    // Security lock register
    // [0] lock_regions
    // [1] lock_ctrl
    // [31:2] reserved
    reg [DATA_WIDTH-1:0] lock_reg;

    // Internal datapath
    reg [3:0] active_region;
    reg       irq_enable;

    // -------------------------------------------------------------------------
    // Reset and write logic
    // -------------------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            ctrl_reg         <= 32'b0;
            status_reg       <= 32'b0;
            region_perm_reg  <= {NUM_REGIONS{1'b0}};
            cfg_reg          <= 32'b0;
            lock_reg         <= 32'b0;
            bus_ready        <= 1'b0;
        end else begin
            bus_ready <= 1'b0;

            if (bus_sel && bus_wr) begin
                bus_ready <= 1'b1;
                case (bus_addr[7:2])
                    6'h00: begin
                        // Control register write
                        // CWE-1233: Missing lock check on lock_ctrl bit
                        ctrl_reg <= bus_wdata;
                    end
                    6'h01: begin
                        // Region permission write
                        // CWE-1233: lock_regions bit exists but is ignored
                        region_perm_reg <= bus_wdata[NUM_REGIONS-1:0];
                    end
                    6'h02: begin
                        // Configuration register
                        cfg_reg <= bus_wdata;
                    end
                    6'h03: begin
                        // Lock register itself (write-once intended, but not enforced)
                        lock_reg <= bus_wdata;
                    end
                    6'h04: begin
                        // Clear status
                        status_reg[0] <= 1'b0;
                    end
                    default: begin
                        // no-op
                    end
                endcase
            end
        end
    end

    // -------------------------------------------------------------------------
    // Read logic
    // -------------------------------------------------------------------------
    always @(*) begin
        bus_rdata = 32'b0;
        if (bus_sel && !bus_wr) begin
            case (bus_addr[7:2])
                6'h00: bus_rdata = ctrl_reg;
                6'h01: bus_rdata = {{(32-NUM_REGIONS){1'b0}}, region_perm_reg};
                6'h02: bus_rdata = cfg_reg;
                6'h03: bus_rdata = lock_reg;
                6'h04: bus_rdata = status_reg;
                default: bus_rdata = 32'b0;
            endcase
        end
    end

    // -------------------------------------------------------------------------
    // State-dependent behavior and datapath logic
    // -------------------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            firewall_enable <= 1'b0;
            irq_enable      <= 1'b0;
            active_region   <= 4'b0;
            violation_irq   <= 1'b0;
        end else begin
            firewall_enable <= ctrl_reg[0];
            irq_enable      <= ctrl_reg[1];
            active_region   <= cfg_reg[3:0];

            // Simple violation detection
            if (firewall_enable &&
                active_region < NUM_REGIONS &&
                !region_perm_reg[active_region]) begin
                status_reg[0] <= 1'b1;
            end

            violation_irq <= status_reg[0] & irq_enable;
        end
    end

    // -------------------------------------------------------------------------
    // Output mapping
    // -------------------------------------------------------------------------
    always @(*) begin
        region_secure = region_perm_reg;
    end

endmodule
