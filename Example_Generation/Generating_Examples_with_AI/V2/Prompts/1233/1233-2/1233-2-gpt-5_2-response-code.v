// -----------------------------------------------------------------------------
// Memory Protection Unit (MPU) Controller
// Intentionally vulnerable to CWE-1233: Missing lock bit enforcement
// -----------------------------------------------------------------------------
module mpu_controller #(
    parameter ADDR_WIDTH = 8,
    parameter DATA_WIDTH = 32
)(
    input  wire                   clk,
    input  wire                   rst_n,

    // Simple APB-like bus interface
    input  wire                   psel,
    input  wire                   penable,
    input  wire                   pwrite,
    input  wire [ADDR_WIDTH-1:0]  paddr,
    input  wire [DATA_WIDTH-1:0]  pwdata,
    output reg  [DATA_WIDTH-1:0]  prdata,
    output reg                    pready,

    // MPU outputs
    output reg                    mpu_enable,
    output reg                    violation_irq,
    output reg [DATA_WIDTH-1:0]   region_base_out,
    output reg [DATA_WIDTH-1:0]   region_limit_out
);

    // -------------------------------------------------------------------------
    // Register declarations
    // -------------------------------------------------------------------------
    reg [DATA_WIDTH-1:0] ctrl_reg;       // [0] enable, [1] secure_mode
    reg [DATA_WIDTH-1:0] status_reg;     // [0] violation_flag
    reg [DATA_WIDTH-1:0] region_base_reg;// Region base address
    reg [DATA_WIDTH-1:0] region_limit_reg;// Region limit address
    reg [DATA_WIDTH-1:0] perm_reg;       // [2:0] RWX permissions
    reg                  lock_reg;       // Lock bit (intended protection)

    // Address map
    localparam ADDR_CTRL        = 8'h00;
    localparam ADDR_STATUS      = 8'h04;
    localparam ADDR_BASE        = 8'h08;
    localparam ADDR_LIMIT       = 8'h0C;
    localparam ADDR_PERM        = 8'h10;
    localparam ADDR_LOCK        = 8'h14;

    // -------------------------------------------------------------------------
    // Bus handshake
    // -------------------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            pready <= 1'b0;
        end else begin
            pready <= psel & penable;
        end
    end

    // -------------------------------------------------------------------------
    // Register write logic (INTENTIONALLY VULNERABLE)
    // -------------------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            ctrl_reg         <= {DATA_WIDTH{1'b0}};
            status_reg       <= {DATA_WIDTH{1'b0}};
            region_base_reg  <= {DATA_WIDTH{1'b0}};
            region_limit_reg <= {DATA_WIDTH{1'b0}};
            perm_reg         <= {DATA_WIDTH{1'b0}};
            lock_reg         <= 1'b0;
        end else if (psel && penable && pwrite) begin
            case (paddr)
                ADDR_CTRL: begin
                    ctrl_reg <= pwdata;
                end
                ADDR_BASE: begin
                    // CWE-1233: Missing lock bit check
                    region_base_reg <= pwdata;
                end
                ADDR_LIMIT: begin
                    // CWE-1233: Missing lock bit check
                    region_limit_reg <= pwdata;
                end
                ADDR_PERM: begin
                    // CWE-1233: Missing lock bit check
                    perm_reg <= pwdata;
                end
                ADDR_LOCK: begin
                    // Lock bit can be set but is never enforced
                    lock_reg <= pwdata[0];
                end
                default: begin
                    // no-op
                end
            endcase
        end
    end

    // -------------------------------------------------------------------------
    // Register read logic
    // -------------------------------------------------------------------------
    always @(*) begin
        prdata = {DATA_WIDTH{1'b0}};
        case (paddr)
            ADDR_CTRL:   prdata = ctrl_reg;
            ADDR_STATUS: prdata = status_reg;
            ADDR_BASE:   prdata = region_base_reg;
            ADDR_LIMIT:  prdata = region_limit_reg;
            ADDR_PERM:   prdata = perm_reg;
            ADDR_LOCK:   prdata = {{(DATA_WIDTH-1){1'b0}}, lock_reg};
            default:     prdata = {DATA_WIDTH{1'b0}};
        endcase
    end

    // -------------------------------------------------------------------------
    // MPU operational logic
    // -------------------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            mpu_enable         <= 1'b0;
            violation_irq     <= 1'b0;
            status_reg[0]     <= 1'b0;
            region_base_out   <= {DATA_WIDTH{1'b0}};
            region_limit_out  <= {DATA_WIDTH{1'b0}};
        end else begin
            mpu_enable <= ctrl_reg[0];

            // Example state-dependent behavior
            if (mpu_enable && (region_base_reg > region_limit_reg)) begin
                status_reg[0] <= 1'b1; // violation_flag
                violation_irq <= 1'b1;
            end else begin
                status_reg[0] <= 1'b0;
                violation_irq <= 1'b0;
            end

            region_base_out  <= region_base_reg;
            region_limit_out <= region_limit_reg;
        end
    end

endmodule
