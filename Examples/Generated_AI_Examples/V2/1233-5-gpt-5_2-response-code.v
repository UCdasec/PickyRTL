// -----------------------------------------------------------------------------
// Firewall / Isolation Controller (INTENTIONALLY VULNERABLE)
// CWE-1233: Security-Sensitive Hardware Controls with Missing Lock Bit Protection
// -----------------------------------------------------------------------------
// Application Domain : Firewall / Isolation Controller
// Interfaces         : Simple APB-like register interface
// NOTE: This module is intentionally vulnerable and must NOT be used as-is.
// -----------------------------------------------------------------------------

module firewall_ctrl #(
    parameter ADDR_WIDTH = 8,
    parameter DATA_WIDTH = 32,
    parameter NUM_REGIONS = 4
)(
    input  wire                     clk,
    input  wire                     rst_n,

    // APB-like interface
    input  wire                     psel,
    input  wire                     penable,
    input  wire                     pwrite,
    input  wire [ADDR_WIDTH-1:0]    paddr,
    input  wire [DATA_WIDTH-1:0]    pwdata,
    output reg  [DATA_WIDTH-1:0]    prdata,
    output reg                      pready,

    // Firewall outputs
    output reg  [NUM_REGIONS-1:0]   region_enable_o,
    output reg                      firewall_active_o,
    output reg                      violation_irq_o
);

    // -------------------------------------------------------------------------
    // Register Map
    // -------------------------------------------------------------------------
    // 0x00 : CTRL_REG
    //        [0]   firewall_enable
    //        [1]   config_lock   (SECURITY LOCK BIT)
    //
    // 0x04 : STATUS_REG
    //        [0]   violation_flag
    //
    // 0x10 - 0x1C : REGION_CFG[n]
    //        [0]   region_enable
    //        [3:1] region_perm
    // -------------------------------------------------------------------------

    // Control and status registers
    reg firewall_enable;
    reg config_lock;                // <-- Intended lock bit (NOT enforced)
    reg violation_flag;

    // Region configuration registers
    reg        region_enable [0:NUM_REGIONS-1];
    reg [2:0]  region_perm   [0:NUM_REGIONS-1];

    // Internal state machine
    typedef enum logic [1:0] {
        IDLE,
        ACTIVE,
        VIOLATION
    } fw_state_t;

    fw_state_t state, next_state;

    integer i;

    // -------------------------------------------------------------------------
    // APB Write Logic (INTENTIONALLY VULNERABLE)
    // -------------------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            firewall_enable <= 1'b0;
            config_lock     <= 1'b0;
            violation_flag  <= 1'b0;
            pready          <= 1'b0;

            for (i = 0; i < NUM_REGIONS; i = i + 1) begin
                region_enable[i] <= 1'b0;
                region_perm[i]   <= 3'b000;
            end
        end else begin
            pready <= 1'b0;

            if (psel && penable && pwrite) begin
                pready <= 1'b1;

                case (paddr)
                    8'h00: begin
                        firewall_enable <= pwdata[0];
                        config_lock     <= pwdata[1];
                    end

                    8'h04: begin
                        violation_flag <= pwdata[0];
                    end

                    // Region configuration registers
                    8'h10, 8'h14, 8'h18, 8'h1C: begin
                        // INTENTIONAL CWE-1233:
                        // Writes to security-critical region registers
                        // DO NOT check config_lock
                        region_enable[(paddr - 8'h10) >> 2] <= pwdata[0];
                        region_perm[(paddr - 8'h10) >> 2]   <= pwdata[3:1];
                    end

                    default: ;
                endcase
            end
        end
    end

    // -------------------------------------------------------------------------
    // APB Read Logic
    // -------------------------------------------------------------------------
    always @(*) begin
        prdata = {DATA_WIDTH{1'b0}};

        if (psel && !pwrite) begin
            case (paddr)
                8'h00: prdata = {30'b0, config_lock, firewall_enable};
                8'h04: prdata = {31'b0, violation_flag};

                8'h10, 8'h14, 8'h18, 8'h1C:
                    prdata = {
                        28'b0,
                        region_perm[(paddr - 8'h10) >> 2],
                        region_enable[(paddr - 8'h10) >> 2]
                    };

                default: prdata = 32'b0;
            endcase
        end
    end

    // -------------------------------------------------------------------------
    // Firewall State Machine (State-Dependent Behavior)
    // -------------------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            state <= IDLE;
        else
            state <= next_state;
    end

    always @(*) begin
        next_state = state;

        case (state)
            IDLE: begin
                if (firewall_enable)
                    next_state = ACTIVE;
            end

            ACTIVE: begin
                if (violation_flag)
                    next_state = VIOLATION;
            end

            VIOLATION: begin
                if (!violation_flag)
                    next_state = ACTIVE;
            end

            default: next_state = IDLE;
        endcase
    end

    // -------------------------------------------------------------------------
    // Output Logic
    // -------------------------------------------------------------------------
    always @(*) begin
        firewall_active_o = (state == ACTIVE);
        violation_irq_o   = (state == VIOLATION);

        for (i = 0; i < NUM_REGIONS; i = i + 1)
            region_enable_o[i] = region_enable[i];
    end

endmodule
