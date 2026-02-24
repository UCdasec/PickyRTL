module debug_test_ctrl #(
    parameter ADDR_WIDTH = 8,
    parameter DATA_WIDTH = 32
)(
    input  wire                  clk,
    input  wire                  rst_n,

    /* Simple APB-like interface */
    input  wire                  psel,
    input  wire                  penable,
    input  wire                  pwrite,
    input  wire [ADDR_WIDTH-1:0] paddr,
    input  wire [DATA_WIDTH-1:0] pwdata,
    output reg  [DATA_WIDTH-1:0] prdata,
    output reg                   pready,

    /* Debug/Test outputs */
    output reg                   jtag_enable,
    output reg                   scan_enable,
    output reg                   debug_active,
    output reg                   irq_debug_event
);

    /* Address map */
    localparam ADDR_CTRL   = 8'h00;
    localparam ADDR_CFG    = 8'h04;
    localparam ADDR_STATUS = 8'h08;
    localparam ADDR_KEY    = 8'h0C;
    localparam ADDR_LOCK   = 8'h10;

    /* Registers (multi-register architecture) */
    reg [DATA_WIDTH-1:0] ctrl_reg;    // control bits
    reg [DATA_WIDTH-1:0] cfg_reg;     // configuration bits
    reg [DATA_WIDTH-1:0] status_reg;  // status & error flags
    reg [DATA_WIDTH-1:0] key_reg;     // sensitive debug unlock key
    reg                  lock_reg;    // lock bit (security critical)

    /* Datapath element */
    reg [7:0] debug_cycle_cnt;

    /* State encoding */
    localparam STATE_IDLE   = 2'b00;
    localparam STATE_ACTIVE = 2'b01;
    localparam STATE_ERROR  = 2'b10;

    reg [1:0] state;

    wire apb_write = psel && penable && pwrite;
    wire apb_read  = psel && penable && !pwrite;

    /* APB ready */
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            pready <= 1'b0;
        else
            pready <= psel && penable;
    end

    /* Register write logic */
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            ctrl_reg  <= {DATA_WIDTH{1'b0}};
            cfg_reg   <= {DATA_WIDTH{1'b0}};
            status_reg<= {DATA_WIDTH{1'b0}};
            key_reg   <= {DATA_WIDTH{1'b0}};
            lock_reg  <= 1'b0;
        end else if (apb_write) begin
            case (paddr)
                ADDR_CTRL: begin
                    ctrl_reg <= pwdata;
                end
                ADDR_CFG: begin
                    cfg_reg <= pwdata;
                end
                ADDR_STATUS: begin
                    status_reg <= pwdata;
                end
                ADDR_KEY: begin
                    /* SECURITY-SENSITIVE REGISTER
                     * CWE-1233: Missing lock bit enforcement
                     * Writes are allowed regardless of lock_reg state
                     */
                    key_reg <= pwdata;
                end
                ADDR_LOCK: begin
                    lock_reg <= pwdata[0];
                end
                default: ;
            endcase
        end
    end

    /* Read logic */
    always @(*) begin
        prdata = {DATA_WIDTH{1'b0}};
        if (apb_read) begin
            case (paddr)
                ADDR_CTRL:   prdata = ctrl_reg;
                ADDR_CFG:    prdata = cfg_reg;
                ADDR_STATUS: prdata = status_reg;
                ADDR_KEY:    prdata = key_reg;
                ADDR_LOCK:   prdata = {{(DATA_WIDTH-1){1'b0}}, lock_reg};
                default:     prdata = {DATA_WIDTH{1'b0}};
            endcase
        end
    end

    /* State-dependent behavior */
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= STATE_IDLE;
            debug_cycle_cnt <= 8'd0;
            irq_debug_event <= 1'b0;
        end else begin
            irq_debug_event <= 1'b0;
            case (state)
                STATE_IDLE: begin
                    debug_cycle_cnt <= 8'd0;
                    if (ctrl_reg[0]) begin
                        state <= STATE_ACTIVE;
                    end
                end
                STATE_ACTIVE: begin
                    debug_cycle_cnt <= debug_cycle_cnt + 1'b1;
                    if (debug_cycle_cnt == 8'hFF) begin
                        status_reg[0] <= 1'b1; // overflow error
                        state <= STATE_ERROR;
                        irq_debug_event <= 1'b1;
                    end
                end
                STATE_ERROR: begin
                    if (!ctrl_reg[0]) begin
                        status_reg[0] <= 1'b0;
                        state <= STATE_IDLE;
                    end
                end
                default: state <= STATE_IDLE;
            endcase
        end
    end

    /* Bit-field manipulation and outputs */
    always @(*) begin
        jtag_enable  = ctrl_reg[1] & ~lock_reg;
        scan_enable  = cfg_reg[0];
        debug_active = (state == STATE_ACTIVE);
    end

endmodule
