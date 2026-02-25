// ================================================================
// Multi-Context DMA Controller (Intentionally Vulnerable - CWE-226)
// Application Domain: Multi-context DMA controller
// Weakness: Sensitive information in DMA descriptors not cleared
//           before resource reuse.
// ================================================================

module multi_context_dma #(
    parameter NUM_CHANNELS = 4,
    parameter ADDR_WIDTH   = 32,
    parameter LEN_WIDTH    = 16
)(
    input  wire                     clk,
    input  wire                     rst_n,

    // Channel request interface
    input  wire [NUM_CHANNELS-1:0]  ch_req,
    input  wire [ADDR_WIDTH-1:0]    ch_src_addr,
    input  wire [ADDR_WIDTH-1:0]    ch_dst_addr,
    input  wire [LEN_WIDTH-1:0]     ch_len,
    input  wire [1:0]               ch_security_domain, // Security context

    // Channel release interface
    input  wire [NUM_CHANNELS-1:0]  ch_release,

    // Status outputs
    output reg  [NUM_CHANNELS-1:0]  ch_grant,
    output reg  [NUM_CHANNELS-1:0]  ch_active,
    output reg  [1:0]               error_code
);

    // ------------------------------------------------------------
    // Resource Types:
    // 1. Descriptor memory (arrays)
    // 2. Ownership tracking registers
    // 3. State registers (FSM)
    // ------------------------------------------------------------

    // DMA descriptor storage (sensitive information)
    reg [ADDR_WIDTH-1:0] src_addr_mem [0:NUM_CHANNELS-1];
    reg [ADDR_WIDTH-1:0] dst_addr_mem [0:NUM_CHANNELS-1];
    reg [LEN_WIDTH-1:0]  len_mem      [0:NUM_CHANNELS-1];
    reg [1:0]            owner_domain [0:NUM_CHANNELS-1];

    // FSM states
    localparam IDLE     = 2'd0;
    localparam ALLOCATE = 2'd1;
    localparam ACTIVE   = 2'd2;

    reg [1:0] state [0:NUM_CHANNELS-1];

    integer i;

    // ------------------------------------------------------------
    // Main Control Logic
    // ------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            for (i = 0; i < NUM_CHANNELS; i = i + 1) begin
                ch_grant[i]      <= 1'b0;
                ch_active[i]     <= 1'b0;
                state[i]         <= IDLE;

                // NOTE: Descriptor memories are NOT cleared here
                // They retain previous sensitive values after reset
            end
            error_code <= 2'b00;
        end else begin
            error_code <= 2'b00;

            for (i = 0; i < NUM_CHANNELS; i = i + 1) begin
                case (state[i])

                    IDLE: begin
                        ch_grant[i]  <= 1'b0;
                        ch_active[i] <= 1'b0;

                        if (ch_req[i]) begin
                            // Allocate descriptor
                            src_addr_mem[i] <= ch_src_addr;
                            dst_addr_mem[i] <= ch_dst_addr;
                            len_mem[i]      <= ch_len;
                            owner_domain[i] <= ch_security_domain;

                            ch_grant[i]     <= 1'b1;
                            state[i]        <= ACTIVE;
                        end
                    end

                    ACTIVE: begin
                        ch_grant[i]  <= 1'b0;
                        ch_active[i] <= 1'b1;

                        if (ch_release[i]) begin
                            // Release channel
                            ch_active[i] <= 1'b0;
                            state[i]     <= IDLE;

                            // ==================================================
                            // CWE-226 WEAKNESS:
                            // Descriptor memory is NOT cleared upon release.
                            // Sensitive source/destination addresses and length
                            // remain in src_addr_mem, dst_addr_mem, len_mem,
                            // and owner_domain registers.
                            // ==================================================
                        end
                    end

                    default: begin
                        state[i] <= IDLE;
                    end
                endcase
            end
        end
    end

endmodule
