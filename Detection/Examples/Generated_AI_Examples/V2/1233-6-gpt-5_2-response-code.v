// -----------------------------------------------------------------------------
// Firewall / Isolation Controller (Intentionally Vulnerable)
// Demonstrates CWE-1233: Missing lock-bit protection on security-critical registers
// -----------------------------------------------------------------------------

module firewall_ctrl #(
    parameter ADDR_WIDTH = 8,
    parameter DATA_WIDTH = 32,
    parameter NUM_DOMAINS = 4
)(
    input  wire                  clk,
    input  wire                  rst_n,

    // Simple APB-like interface
    input  wire                  psel,
    input  wire                  penable,
    input  wire                  pwrite,
    input  wire [ADDR_WIDTH-1:0] paddr,
    input  wire [DATA_WIDTH-1:0] pwdata,
    output reg  [DATA_WIDTH-1:0] prdata,
    output reg                   pready,

    // Firewall outputs
    output reg  [NUM_DOMAINS-1:0] domain_enable_o,
    output reg                   firewall_active_o,
    output reg                   violation_irq_o
);

    // -------------------------------------------------------------------------
    // Register definitions
    // -------------------------------------------------------------------------

    // Configuration register
    // [0]     firewall_enable
    // [1]     secure_mode
    // [31:2]  reserved
    reg [DATA_WIDTH-1:0] cfg_reg;

    // Domain permission register (one bit per domain)
    reg [NUM_DOMAINS-1:0] domain_perm_reg;

    // Status register
    // [0] violation_detected
    // [1] busy
    reg [DATA_WIDTH-1:0] status_reg;

    // Error address register (captures last faulting address)
    reg [DATA_WIDTH-1:0] error_addr_reg;

    // Lock register (intended to protect configuration)
    // [0] cfg_lock
    reg lock_reg;

    // Internal state
    reg [1:0] op_state;

    localparam IDLE  = 2'b00;
    localparam CHECK = 2'b01;
    localparam FAULT = 2'b10;

    // Address map
    localparam ADDR_CFG        = 8'h00;
    localparam ADDR_DOMAIN     = 8'h04;
    localparam ADDR_STATUS     = 8'h08;
    localparam ADDR_ERROR_ADDR = 8'h0C;
    localparam ADDR_LOCK       = 8'h10;

    wire write_en = psel && penable && pwrite;
    wire read_en  = psel && penable && !pwrite;

    // -------------------------------------------------------------------------
    // Write logic (INTENTIONALLY VULNERABLE)
    // -------------------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            cfg_reg          <= 32'b0;
            domain_perm_reg  <= {NUM_DOMAINS{1'b0}};
            status_reg       <= 32'b0;
            error_addr_reg   <= 32'b0;
            lock_reg         <= 1'b0;
            op_state         <= IDLE;
        end else begin
            // Default status behavior
            status_reg[1] <= (op_state != IDLE);

            if (write_en) begin
                case (paddr)
                    ADDR_CFG: begin
                        // CWE-1233:
                        // cfg_reg controls firewall enable and secure mode
                        // Writes are allowed EVEN WHEN lock_reg IS SET
                        cfg_reg <= pwdata;
                    end

                    ADDR_DOMAIN: begin
                        // Domain permissions are also security-sensitive
                        // Missing lock check here as well
                        domain_perm_reg <= pwdata[NUM_DOMAINS-1:0];
                    end

                    ADDR_STATUS: begin
                        // Writing clears violation flag
                        status_reg[0] <= pwdata[0];
                    end

                    ADDR_ERROR_ADDR: begin
                        error_addr_reg <= pwdata;
                    end

                    ADDR_LOCK: begin
                        // Lock bit itself is writable
                        lock_reg <= pwdata[0];
                    end

                    default: ;
                endcase
            end

            // Simple state machine
            case (op_state)
                IDLE: begin
                    if (cfg_reg[0]) begin
                        op_state <= CHECK;
                    end
                end

                CHECK: begin
                    if (!cfg_reg[1]) begin
                        // Violation if not in secure mode
                        status_reg[0] <= 1'b1;
                        error_addr_reg <= {24'b0, paddr};
                        op_state <= FAULT;
                    end
                end

                FAULT: begin
                    op_state <= IDLE;
                end
            endcase
        end
    end

    // -------------------------------------------------------------------------
    // Read logic
    // -------------------------------------------------------------------------
    always @(*) begin
        prdata = 32'b0;
        pready = 1'b1;

        if (read_en) begin
            case (paddr)
                ADDR_CFG:        prdata = cfg_reg;
                ADDR_DOMAIN:     prdata = {{(32-NUM_DOMAINS){1'b0}}, domain_perm_reg};
                ADDR_STATUS:     prdata = status_reg;
                ADDR_ERROR_ADDR: prdata = error_addr_reg;
                ADDR_LOCK:       prdata = {31'b0, lock_reg};
                default:         prdata = 32'b0;
            endcase
        end
    end

    // -------------------------------------------------------------------------
    // Outputs
    // -------------------------------------------------------------------------
    always @(*) begin
        firewall_active_o = cfg_reg[0];
        domain_enable_o   = domain_perm_reg;
        violation_irq_o   = status_reg[0];
    end

endmodule
