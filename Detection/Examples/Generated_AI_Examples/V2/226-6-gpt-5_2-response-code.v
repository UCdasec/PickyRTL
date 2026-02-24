// ================================================================
// Multi-Context DMA Controller (Intentionally Vulnerable - CWE-226)
// Application Domain: Multi-context DMA controller
// Weakness: Sensitive Information in Resource Not Removed Before Reuse
// ================================================================

module multi_context_dma #(
    parameter NUM_CHANNELS = 4,
    parameter ADDR_WIDTH   = 32,
    parameter DATA_WIDTH   = 32
)(
    input  wire                         clk,
    input  wire                         rst_n,

    // Request interface
    input  wire                         req_valid,
    input  wire [1:0]                   req_domain,     // Security domain ID
    input  wire [ADDR_WIDTH-1:0]        req_src_addr,
    input  wire [ADDR_WIDTH-1:0]        req_dst_addr,
    input  wire [15:0]                  req_length,
    input  wire                         req_write,

    output reg                          req_grant,
    output reg                          dma_done,
    output reg                          dma_error
);

    // ============================================================
    // Resource Types:
    // 1. Register arrays for channel configuration
    // 2. Internal buffer memory per channel
    // 3. Status and ownership tracking registers
    // ============================================================

    // Channel configuration registers
    reg [ADDR_WIDTH-1:0] src_addr     [0:NUM_CHANNELS-1];
    reg [ADDR_WIDTH-1:0] dst_addr     [0:NUM_CHANNELS-1];
    reg [15:0]           length_reg   [0:NUM_CHANNELS-1];
    reg [1:0]            owner_domain [0:NUM_CHANNELS-1];

    // Status tracking
    reg                  channel_allocated [0:NUM_CHANNELS-1];
    reg                  channel_active    [0:NUM_CHANNELS-1];

    // Internal staging buffer (simulates sensitive data holding area)
    reg [DATA_WIDTH-1:0] dma_buffer [0:NUM_CHANNELS-1][0:7];

    // FSM
    localparam IDLE      = 2'd0;
    localparam ALLOCATE  = 2'd1;
    localparam TRANSFER  = 2'd2;
    localparam COMPLETE  = 2'd3;

    reg [1:0] state;
    reg [1:0] current_channel;
    integer i;
    integer j;

    // ============================================================
    // Channel Allocation Logic (Simple priority: lowest index free)
    // ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state       <= IDLE;
            req_grant   <= 1'b0;
            dma_done    <= 1'b0;
            dma_error   <= 1'b0;
            current_channel <= 2'd0;

            for (i = 0; i < NUM_CHANNELS; i = i + 1) begin
                channel_allocated[i] <= 1'b0;
                channel_active[i]    <= 1'b0;
                owner_domain[i]      <= 2'd0;
                src_addr[i]          <= {ADDR_WIDTH{1'b0}};
                dst_addr[i]          <= {ADDR_WIDTH{1'b0}};
                length_reg[i]        <= 16'd0;

                for (j = 0; j < 8; j = j + 1) begin
                    dma_buffer[i][j] <= {DATA_WIDTH{1'b0}};
                end
            end
        end else begin
            req_grant <= 1'b0;
            dma_done  <= 1'b0;
            dma_error <= 1'b0;

            case (state)

                IDLE: begin
                    if (req_valid) begin
                        state <= ALLOCATE;
                    end
                end

                // Allocate first free channel
                ALLOCATE: begin
                    for (i = 0; i < NUM_CHANNELS; i = i + 1) begin
                        if (!channel_allocated[i]) begin
                            current_channel <= i[1:0];
                            channel_allocated[i] <= 1'b1;
                            channel_active[i]    <= 1'b1;
                            owner_domain[i]      <= req_domain;
                            src_addr[i]          <= req_src_addr;
                            dst_addr[i]          <= req_dst_addr;
                            length_reg[i]        <= req_length;
                            req_grant            <= 1'b1;
                            state                <= TRANSFER;
                        end
                    end
                end

                // Simulated transfer (populate buffer with pseudo-sensitive data)
                TRANSFER: begin
                    for (j = 0; j < 8; j = j + 1) begin
                        dma_buffer[current_channel][j] 
                            <= src_addr[current_channel] ^ dst_addr[current_channel] ^ j;
                    end
                    state <= COMPLETE;
                end

                // Release channel
                COMPLETE: begin
                    channel_active[current_channel] <= 1'b0;
                    channel_allocated[current_channel] <= 1'b0;

                    // ====================================================
                    // CWE-226 Vulnerability:
                    // Sensitive buffer and configuration registers are
                    // NOT cleared before the channel is made available
                    // for reuse by another security domain.
                    //
                    // dma_buffer, src_addr, dst_addr, length_reg, and
                    // owner_domain retain previous domain's data.
                    // ====================================================

                    dma_done <= 1'b1;
                    state    <= IDLE;
                end

                default: state <= IDLE;

            endcase
        end
    end

endmodule
