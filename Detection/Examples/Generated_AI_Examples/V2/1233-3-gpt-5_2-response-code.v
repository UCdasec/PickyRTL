module debug_test_ctrl #(
    parameter ADDR_WIDTH = 8,
    parameter DATA_WIDTH = 32
)(
    input  wire                   pclk,
    input  wire                   presetn,

    // APB-like interface
    input  wire                   psel,
    input  wire                   penable,
    input  wire                   pwrite,
    input  wire [ADDR_WIDTH-1:0]  paddr,
    input  wire [DATA_WIDTH-1:0]  pwdata,
    output reg  [DATA_WIDTH-1:0]  prdata,
    output reg                    pready,

    // External control/status
    input  wire                   dbg_req,
    output reg                    dbg_enable,
    output reg                    jtag_unlock,
    output reg                    irq
);

    // Address map
    localparam ADDR_CTRL      = 8'h00;
    localparam ADDR_STATUS    = 8'h04;
    localparam ADDR_DEBUGKEY  = 8'h08;
    localparam ADDR_LOCK      = 8'h0C;
    localparam ADDR_COUNTER   = 8'h10;

    // Registers
    reg [DATA_WIDTH-1:0] ctrl_reg;        // control bits
    reg [DATA_WIDTH-1:0] status_reg;      // status flags
    reg [DATA_WIDTH-1:0] debug_key_reg;   // security-sensitive debug key
    reg                  lock_reg;        // lock bit
    reg [DATA_WIDTH-1:0] counter_reg;     // activity counter

    // Bit fields
    wire ctrl_enable = ctrl_reg[0];
    wire ctrl_mode   = ctrl_reg[2:1];

    // APB ready is always one cycle response
    always @(posedge pclk or negedge presetn) begin
        if (!presetn)
            pready <= 1'b0;
        else
            pready <= psel & penable;
    end

    // Write logic
    always @(posedge pclk or negedge presetn) begin
        if (!presetn) begin
            ctrl_reg       <= {DATA_WIDTH{1'b0}};
            status_reg     <= {DATA_WIDTH{1'b0}};
            debug_key_reg  <= {DATA_WIDTH{1'b0}};
            lock_reg       <= 1'b0;
            counter_reg    <= {DATA_WIDTH{1'b0}};
        end else begin
            // increment counter when debug is active
            if (dbg_enable)
                counter_reg <= counter_reg + 1'b1;

            if (psel && penable && pwrite) begin
                case (paddr)
                    ADDR_CTRL: begin
                        // CTRL is protected by lock
                        if (!lock_reg)
                            ctrl_reg <= pwdata;
                    end

                    ADDR_DEBUGKEY: begin
                        // CWE-1233 VULNERABILITY:
                        // Security-sensitive debug key write
                        // is NOT protected by the lock bit
                        debug_key_reg <= pwdata;
                    end

                    ADDR_LOCK: begin
                        // lock can only be set, never cleared
                        lock_reg <= lock_reg | pwdata[0];
                    end

                    default: ;
                endcase
            end

            // status update
            status_reg[0] <= dbg_req;
            status_reg[1] <= lock_reg;
        end
    end

    // Read logic
    always @(*) begin
        case (paddr)
            ADDR_CTRL:     prdata = ctrl_reg;
            ADDR_STATUS:   prdata = status_reg;
            ADDR_DEBUGKEY: prdata = debug_key_reg;
            ADDR_LOCK:     prdata = {{(DATA_WIDTH-1){1'b0}}, lock_reg};
            ADDR_COUNTER:  prdata = counter_reg;
            default:       prdata = {DATA_WIDTH{1'b0}};
        endcase
    end

    // State-dependent behavior
    always @(posedge pclk or negedge presetn) begin
        if (!presetn) begin
            dbg_enable  <= 1'b0;
            jtag_unlock <= 1'b0;
            irq         <= 1'b0;
        end else begin
            dbg_enable  <= ctrl_enable & dbg_req;

            // JTAG unlock depends on debug key value
            if (debug_key_reg == 32'hDEADBEEF)
                jtag_unlock <= 1'b1;

            // Interrupt when counter overflows
            if (counter_reg == {DATA_WIDTH{1'b1}})
                irq <= 1'b1;
        end
    end

endmodule
