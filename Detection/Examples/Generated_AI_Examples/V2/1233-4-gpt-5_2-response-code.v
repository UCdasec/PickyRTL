//------------------------------------------------------------------------------
// Firewall / Isolation Controller (Intentionally Vulnerable)
// CWE-1233: Security-Sensitive Hardware Controls with Missing Lock Bit Protection
//------------------------------------------------------------------------------
//
// Application Domain:
//   Firewall / isolation controller managing access permissions between
//   secure and non-secure bus masters.
//
// NOTE:
//   This design intentionally allows writes to security-critical registers
//   even when a lock bit is asserted.
//
//------------------------------------------------------------------------------

module firewall_ctrl #(
    parameter integer ADDR_WIDTH = 8,
    parameter integer DATA_WIDTH = 32,
    parameter integer NUM_REGIONS = 4
)(
    // Clock and reset
    input  wire                    clk,
    input  wire                    rst_n,

    // Simple APB-like configuration interface
    input  wire                    psel,
    input  wire                    penable,
    input  wire                    pwrite,
    input  wire [ADDR_WIDTH-1:0]   paddr,
    input  wire [DATA_WIDTH-1:0]   pwdata,
    output reg  [DATA_WIDTH-1:0]   prdata,
    output reg                     pready,

    // Firewall outputs
    output reg  [NUM_REGIONS-1:0]  region_enable_o,
    output reg                     firewall_active_o,
    output reg                     intr_o
);

    //--------------------------------------------------------------------------
    // Internal Registers (multi-register architecture)
    //--------------------------------------------------------------------------

    // Control register
    // [0]   firewall_enable
    // [1]   secure_mode
    // [31:2] reserved
    reg [DATA_WIDTH-1:0] ctrl_reg;

    // Status register
    // [0] violation_detected
    // [1] busy
    reg [DATA_WIDTH-1:0] status_reg;

    // Security-sensitive region permission registers
    // Each bit enables access to a region
    reg [NUM_REGIONS-1:0] region_perm_reg;

    // Configuration register for region behavior
    // [3:0] default_region
    // [7:4] reserved
    reg [DATA_WIDTH-1:0] region_cfg_reg;

    // Lock register (security lock bit)
    // [0] cfg_lock  (intended to lock configuration registers)
    reg [DATA_WIDTH-1:0] lock_reg;

    //--------------------------------------------------------------------------
    // Internal datapath / state logic
    //--------------------------------------------------------------------------

    reg [1:0] op_state;
    localparam IDLE  = 2'd0;
    localparam CHECK = 2'd1;
    localparam ERROR = 2'd2;

    reg [7:0] violation_counter;

    wire write_en = psel && penable && pwrite;
    wire read_en  = psel && penable && !pwrite;

    //--------------------------------------------------------------------------
    // Write logic (INTENTIONALLY VULNERABLE)
    //--------------------------------------------------------------------------

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            ctrl_reg            <= {DATA_WIDTH{1'b0}};
            status_reg          <= {DATA_WIDTH{1'b0}};
            region_perm_reg     <= {NUM_REGIONS{1'b0}};
            region_cfg_reg      <= {DATA_WIDTH{1'b0}};
            lock_reg            <= {DATA_WIDTH{1'b0}};
            pready              <= 1'b0;
        end else begin
            pready <= 1'b1;

            if (write_en) begin
                case (paddr[5:2])
                    4'h0: ctrl_reg        <= pwdata;

                    4'h1: status_reg      <= pwdata; // writable for test/debug

                    // SECURITY-SENSITIVE REGISTERS
                    // CWE-1233:
                    // These registers SHOULD check lock_reg[0] before writing.
                    // The check is MISSING, so writes are always allowed.
                    4'h2: region_perm_reg <= pwdata[NUM_REGIONS-1:0];
                    4'h3: region_cfg_reg  <= pwdata;

                    // Lock register itself
                    4'h4: lock_reg        <= pwdata;

                    default: ;
                endcase
            end
        end
    end

    //--------------------------------------------------------------------------
    // Read logic
    //--------------------------------------------------------------------------

    always @(*) begin
        prdata = {DATA_WIDTH{1'b0}};
        if (read_en) begin
            case (paddr[5:2])
                4'h0: prdata = ctrl_reg;
                4'h1: prdata = status_reg;
                4'h2: prdata = {{(DATA_WIDTH-NUM_REGIONS){1'b0}}, region_perm_reg};
                4'h3: prdata = region_cfg_reg;
                4'h4: prdata = lock_reg;
                default: prdata = {DATA_WIDTH{1'b0}};
            endcase
        end
    end

    //--------------------------------------------------------------------------
    // State-dependent behavior and datapath
    //--------------------------------------------------------------------------

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            op_state            <= IDLE;
            violation_counter  <= 8'd0;
            status_reg[0]      <= 1'b0; // violation_detected
            status_reg[1]      <= 1'b0; // busy
            intr_o             <= 1'b0;
        end else begin
            intr_o <= 1'b0;

            case (op_state)
                IDLE: begin
                    status_reg[1] <= 1'b0;
                    if (ctrl_reg[0]) begin
                        op_state       <= CHECK;
                        status_reg[1]  <= 1'b1;
                    end
                end

                CHECK: begin
                    // Simple example condition for a violation
                    if (ctrl_reg[1] && (region_perm_reg == {NUM_REGIONS{1'b0}})) begin
                        status_reg[0] <= 1'b1;
                        violation_counter <= violation_counter + 1'b1;
                        intr_o <= 1'b1;
                        op_state <= ERROR;
                    end else begin
                        op_state <= IDLE;
                    end
                end

                ERROR: begin
                    // Remain in error until firewall disabled
                    if (!ctrl_reg[0]) begin
                        status_reg[0] <= 1'b0;
                        op_state <= IDLE;
                    end
                end

                default: op_state <= IDLE;
            endcase
        end
    end

    //--------------------------------------------------------------------------
    // Outputs
    //--------------------------------------------------------------------------

    always @(*) begin
        firewall_active_o = ctrl_reg[0];
        region_enable_o   = region_perm_reg;
    end

endmodule
