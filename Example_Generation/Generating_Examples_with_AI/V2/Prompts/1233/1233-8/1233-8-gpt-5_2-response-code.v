// Debug and Test Interface Controller (INTENTIONALLY VULNERABLE)
// CWE-1233: Security-Sensitive Hardware Controls with Missing Lock Bit Protection

module debug_test_ctrl #(
    parameter ADDR_WIDTH = 8,
    parameter DATA_WIDTH = 32
)(
    // APB-like bus interface
    input  wire                  clk,
    input  wire                  rst_n,
    input  wire                  psel,
    input  wire                  penable,
    input  wire                  pwrite,
    input  wire [ADDR_WIDTH-1:0] paddr,
    input  wire [DATA_WIDTH-1:0] pwdata,
    output reg  [DATA_WIDTH-1:0] prdata,
    output reg                   pready,

    // External control/status
    input  wire                  debug_req,
    output reg                   debug_enable,
    output reg                   jtag_enable,
    output reg                   scan_enable,
    output reg                   intr_debug
);

    // ------------------------------------------------------------
    // Register address map
    // ------------------------------------------------------------
    localparam ADDR_CTRL     = 8'h00; // Control register (security-sensitive)
    localparam ADDR_STATUS   = 8'h04; // Status register
    localparam ADDR_KEY      = 8'h08; // Debug unlock key register (security-sensitive)
    localparam ADDR_LOCK     = 8'h0C; // Lock register
    localparam ADDR_COUNTER  = 8'h10; // Debug event counter

    // ------------------------------------------------------------
    // Registers
    // ------------------------------------------------------------
    reg [DATA_WIDTH-1:0] ctrl_reg;     // [0]=debug_en, [1]=jtag_en, [2]=scan_en
    reg [DATA_WIDTH-1:0] status_reg;   // [0]=debug_active, [1]=error_flag
    reg [DATA_WIDTH-1:0] key_reg;      // Security-sensitive debug key
    reg                  lock_reg;     // Lock bit (intended to protect ctrl_reg & key_reg)
    reg [DATA_WIDTH-1:0] dbg_counter;  // Counts debug requests

    // ------------------------------------------------------------
    // State-dependent behavior
    // ------------------------------------------------------------
    wire debug_active = ctrl_reg[0] & debug_req;

    // ------------------------------------------------------------
    // Sequential logic
    // ------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            ctrl_reg     <= {DATA_WIDTH{1'b0}};
            status_reg   <= {DATA_WIDTH{1'b0}};
            key_reg      <= {DATA_WIDTH{1'b0}};
            lock_reg     <= 1'b0;
            dbg_counter  <= {DATA_WIDTH{1'b0}};
            pready       <= 1'b0;
            prdata       <= {DATA_WIDTH{1'b0}};
            intr_debug   <= 1'b0;
        end else begin
            pready     <= 1'b0;
            intr_debug <= 1'b0;

            // Debug activity tracking
            if (debug_active) begin
                dbg_counter        <= dbg_counter + 1'b1;
                status_reg[0]      <= 1'b1;
                intr_debug         <= 1'b1;
            end else begin
                status_reg[0]      <= 1'b0;
            end

            // ----------------------------------------------------
            // APB-like write transactions
            // ----------------------------------------------------
            if (psel && penable && pwrite) begin
                pready <= 1'b1;
                case (paddr)
                    ADDR_CTRL: begin
                        // CWE-1233 VULNERABILITY:
                        // Missing check of lock_reg before modifying ctrl_reg
                        ctrl_reg <= pwdata;
                    end
                    ADDR_KEY: begin
                        // CWE-1233 VULNERABILITY:
                        // Security-sensitive debug key is writable even when locked
                        key_reg <= pwdata;
                    end
                    ADDR_LOCK: begin
                        lock_reg <= pwdata[0];
                    end
                    default: begin
                        // no-op
                    end
                endcase
            end

            // ----------------------------------------------------
            // APB-like read transactions
            // ----------------------------------------------------
            if (psel && penable && !pwrite) begin
                pready <= 1'b1;
                case (paddr)
                    ADDR_CTRL:    prdata <= ctrl_reg;
                    ADDR_STATUS:  prdata <= status_reg;
                    ADDR_KEY:     prdata <= key_reg;
                    ADDR_LOCK:    prdata <= {{(DATA_WIDTH-1){1'b0}}, lock_reg};
                    ADDR_COUNTER: prdata <= dbg_counter;
                    default:      prdata <= {DATA_WIDTH{1'b0}};
                endcase
            end
        end
    end

    // ------------------------------------------------------------
    // Output assignments
    // ------------------------------------------------------------
    always @(*) begin
        debug_enable = ctrl_reg[0];
        jtag_enable  = ctrl_reg[1];
        scan_enable  = ctrl_reg[2];
    end

endmodule
