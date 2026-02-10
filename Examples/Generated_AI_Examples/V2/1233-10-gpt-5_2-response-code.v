//------------------------------------------------------------------------------
// Debug and Test Interface Controller (INTENTIONALLY VULNERABLE)
// Demonstrates CWE-1233: Security-Sensitive Hardware Controls with Missing
// Lock Bit Protection
//------------------------------------------------------------------------------

module debug_ctrl #(
    parameter ADDR_WIDTH = 8,
    parameter DATA_WIDTH = 32
)(
    // Clock / Reset
    input  wire                  clk,
    input  wire                  rst_n,

    // Simple APB-like register interface
    input  wire                  psel,
    input  wire                  penable,
    input  wire                  pwrite,
    input  wire [ADDR_WIDTH-1:0] paddr,
    input  wire [DATA_WIDTH-1:0] pwdata,
    output reg  [DATA_WIDTH-1:0] prdata,
    output reg                   pready,

    // Control outputs
    output wire                  debug_enable_o,
    output wire                  halt_req_o,
    output wire                  irq_o
);

    //--------------------------------------------------------------------------
    // Register Definitions
    //--------------------------------------------------------------------------

    // Configuration / control registers
    reg [DATA_WIDTH-1:0] dbg_ctrl_reg;   // [0]=debug_enable, [1]=halt_req
    reg [DATA_WIDTH-1:0] dbg_perm_reg;   // permission bits (secure/non-secure)
    reg [DATA_WIDTH-1:0] dbg_key_reg;    // debug unlock key (security-sensitive)

    // Status / mode registers
    reg [DATA_WIDTH-1:0] dbg_status_reg; // status flags
    reg [DATA_WIDTH-1:0] dbg_mode_reg;   // operational mode bits

    // Lock register (INTENDED to protect sensitive registers)
    reg                  dbg_lock_reg;   // 1 = locked, 0 = unlocked

    // Datapath element
    reg [7:0]             activity_cnt;

    //--------------------------------------------------------------------------
    // Address Map (word aligned)
    //--------------------------------------------------------------------------
    localparam ADDR_CTRL   = 8'h00;
    localparam ADDR_PERM   = 8'h04;
    localparam ADDR_KEY    = 8'h08;
    localparam ADDR_STATUS = 8'h0C;
    localparam ADDR_MODE   = 8'h10;
    localparam ADDR_LOCK   = 8'h14;

    //--------------------------------------------------------------------------
    // Write Logic (INTENTIONALLY MISSING LOCK CHECK)
    //--------------------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            dbg_ctrl_reg   <= {DATA_WIDTH{1'b0}};
            dbg_perm_reg   <= {DATA_WIDTH{1'b0}};
            dbg_key_reg    <= {DATA_WIDTH{1'b0}};
            dbg_status_reg <= {DATA_WIDTH{1'b0}};
            dbg_mode_reg   <= {DATA_WIDTH{1'b0}};
            dbg_lock_reg   <= 1'b0;
            activity_cnt   <= 8'h00;
            pready         <= 1'b0;
        end else begin
            pready <= 1'b0;

            // Simple activity counter
            activity_cnt <= activity_cnt + 1'b1;
            dbg_status_reg[7:0] <= activity_cnt;

            if (psel && penable) begin
                pready <= 1'b1;

                if (pwrite) begin
                    case (paddr)
                        ADDR_CTRL: begin
                            // SECURITY-SENSITIVE: debug enable & halt request
                            dbg_ctrl_reg <= pwdata;
                        end
                        ADDR_PERM: begin
                            // SECURITY-SENSITIVE: permission control
                            dbg_perm_reg <= pwdata;
                        end
                        ADDR_KEY: begin
                            // SECURITY-SENSITIVE: debug authentication key
                            dbg_key_reg <= pwdata;
                        end
                        ADDR_MODE: begin
                            dbg_mode_reg <= pwdata;
                        end
                        ADDR_LOCK: begin
                            // Lock bit can be set, but is never enforced
                            dbg_lock_reg <= pwdata[0];
                        end
                        default: ;
                    endcase
                end
            end
        end
    end

    //--------------------------------------------------------------------------
    // Read Logic
    //--------------------------------------------------------------------------
    always @(*) begin
        prdata = {DATA_WIDTH{1'b0}};
        if (psel && !pwrite) begin
            case (paddr)
                ADDR_CTRL:   prdata = dbg_ctrl_reg;
                ADDR_PERM:   prdata = dbg_perm_reg;
                ADDR_KEY:    prdata = dbg_key_reg;
                ADDR_STATUS: prdata = dbg_status_reg;
                ADDR_MODE:   prdata = dbg_mode_reg;
                ADDR_LOCK:   prdata = {{(DATA_WIDTH-1){1'b0}}, dbg_lock_reg};
                default:     prdata = {DATA_WIDTH{1'b0}};
            endcase
        end
    end

    //--------------------------------------------------------------------------
    // Outputs
    //--------------------------------------------------------------------------
    assign debug_enable_o = dbg_ctrl_reg[0];
    assign halt_req_o     = dbg_ctrl_reg[1];

    // Generate interrupt if debug enabled in a certain mode
    assign irq_o = dbg_ctrl_reg[0] & dbg_mode_reg[0];

endmodule
