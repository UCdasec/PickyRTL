module firewall_isolation_ctrl #(
    parameter ADDR_WIDTH = 8,
    parameter DATA_WIDTH = 32
)(
    input  wire                    clk,
    input  wire                    rst_n,

    /* Simple APB-like control interface */
    input  wire                    psel,
    input  wire                    penable,
    input  wire                    pwrite,
    input  wire [ADDR_WIDTH-1:0]   paddr,
    input  wire [DATA_WIDTH-1:0]   pwdata,
    output reg  [DATA_WIDTH-1:0]   prdata,
    output reg                     pready,

    /* Security / datapath inputs */
    input  wire                    access_violation_in,

    /* Firewall outputs */
    output wire                    firewall_enable,
    output wire                    violation_irq,
    output wire [DATA_WIDTH-1:0]   region_base_out,
    output wire [DATA_WIDTH-1:0]   region_mask_out,
    output wire [7:0]              region_perm_out
);

    /* Address map */
    localparam ADDR_CTRL       = 8'h00;
    localparam ADDR_REGION_BASE= 8'h04;
    localparam ADDR_REGION_MASK= 8'h08;
    localparam ADDR_REGION_PERM= 8'h0C;
    localparam ADDR_STATUS     = 8'h10;
    localparam ADDR_LOCK       = 8'h14;

    /* Registers */
    reg [DATA_WIDTH-1:0] ctrl_reg;        // [0] enable, [1] irq_enable, [3:2] mode
    reg [DATA_WIDTH-1:0] region_base_reg; // region base address
    reg [DATA_WIDTH-1:0] region_mask_reg; // region mask
    reg [DATA_WIDTH-1:0] region_perm_reg; // [7:0] permissions
    reg [DATA_WIDTH-1:0] status_reg;      // [0] violation_seen
    reg [DATA_WIDTH-1:0] lock_reg;        // [0] lock bit (intended protection)

    /* Datapath / state */
    reg [3:0] violation_cnt;
    reg       run_state;

    /* Output assigns */
    assign firewall_enable  = ctrl_reg[0];
    assign violation_irq   = ctrl_reg[1] & status_reg[0];
    assign region_base_out = region_base_reg;
    assign region_mask_out = region_mask_reg;
    assign region_perm_out = region_perm_reg[7:0];

    /* APB ready */
    always @(*) begin
        pready = psel & penable;
    end

    /* Write logic */
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            ctrl_reg        <= 32'h0;
            region_base_reg <= 32'h0;
            region_mask_reg <= 32'h0;
            region_perm_reg <= 32'h0;
            status_reg      <= 32'h0;
            lock_reg        <= 32'h0;
            violation_cnt   <= 4'h0;
            run_state       <= 1'b0;
        end else begin
            /* State-dependent behavior */
            run_state <= ctrl_reg[0];

            /* Count violations when enabled */
            if (run_state && access_violation_in) begin
                violation_cnt <= violation_cnt + 1'b1;
                status_reg[0] <= 1'b1;
            end

            /* APB write access */
            if (psel && penable && pwrite) begin
                case (paddr)
                    ADDR_CTRL: begin
                        ctrl_reg <= pwdata;
                    end
                    ADDR_REGION_BASE: begin
                        region_base_reg <= pwdata;
                    end
                    ADDR_REGION_MASK: begin
                        region_mask_reg <= pwdata;
                    end
                    ADDR_REGION_PERM: begin
                        region_perm_reg <= pwdata;
                    end
                    ADDR_STATUS: begin
                        status_reg <= pwdata; // writable status
                    end
                    ADDR_LOCK: begin
                        lock_reg <= pwdata;
                    end
                    default: begin
                        /* no-op */
                    end
                endcase
            end
        end
    end

    /* Read logic */
    always @(*) begin
        prdata = {DATA_WIDTH{1'b0}};
        if (psel && !pwrite) begin
            case (paddr)
                ADDR_CTRL:        prdata = ctrl_reg;
                ADDR_REGION_BASE: prdata = region_base_reg;
                ADDR_REGION_MASK: prdata = region_mask_reg;
                ADDR_REGION_PERM: prdata = region_perm_reg;
                ADDR_STATUS:      prdata = status_reg;
                ADDR_LOCK:        prdata = lock_reg;
                default:          prdata = 32'h0;
            endcase
        end
    end

endmodule
