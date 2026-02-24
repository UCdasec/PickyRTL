// ================================================================
// Shared Cryptographic Accelerator with Key Slot Management
// Intentionally vulnerable to CWE-226:
// Sensitive Information in Resource Not Removed Before Reuse
// ================================================================

module shared_crypto_accel #(
    parameter NUM_SLOTS  = 4,      // Number of key slots (multi-user support)
    parameter DATA_WIDTH = 128,    // Key and data width
    parameter USER_WIDTH = 2       // User ID width
)(
    input  wire                     clk,
    input  wire                     rst_n,

    // Request interface
    input  wire                     req_valid,
    input  wire                     req_alloc,      // 1 = allocate, 0 = release
    input  wire [USER_WIDTH-1:0]    req_user_id,
    input  wire [DATA_WIDTH-1:0]    req_key_data,

    // Status outputs
    output reg                      grant_valid,
    output reg  [1:0]               grant_slot_id,
    output reg                      error_flag
);

    // ============================================================
    // Resource Types:
    //   1. Key storage memory (key_mem)
    //   2. Ownership tracking registers (owner_id)
    //   3. Allocation state registers (slot_allocated)
    // ============================================================

    reg [DATA_WIDTH-1:0] key_mem [0:NUM_SLOTS-1];       // Sensitive key storage
    reg [USER_WIDTH-1:0] owner_id [0:NUM_SLOTS-1];      // Tracks which user owns slot
    reg                  slot_allocated [0:NUM_SLOTS-1];

    // ============================================================
    // FSM States for Resource Lifecycle
    // ============================================================

    localparam IDLE      = 2'd0;
    localparam ALLOCATE  = 2'd1;
    localparam RELEASE   = 2'd2;

    reg [1:0] state;
    integer i;

    // ============================================================
    // FSM and Resource Management Logic
    // ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state        <= IDLE;
            grant_valid  <= 1'b0;
            grant_slot_id<= 2'd0;
            error_flag   <= 1'b0;

            for (i = 0; i < NUM_SLOTS; i = i + 1) begin
                slot_allocated[i] <= 1'b0;
                owner_id[i]       <= {USER_WIDTH{1'b0}};
                // NOTE: key_mem is NOT cleared on reset
            end
        end else begin
            grant_valid <= 1'b0;
            error_flag  <= 1'b0;

            case (state)
                IDLE: begin
                    if (req_valid && req_alloc)
                        state <= ALLOCATE;
                    else if (req_valid && !req_alloc)
                        state <= RELEASE;
                end

                // ====================================================
                // Allocation Logic (Priority: lowest index first)
                // ====================================================
                ALLOCATE: begin
                    for (i = 0; i < NUM_SLOTS; i = i + 1) begin
                        if (!slot_allocated[i] && !grant_valid) begin
                            slot_allocated[i] <= 1'b1;
                            owner_id[i]       <= req_user_id;
                            key_mem[i]        <= req_key_data; // Store sensitive key
                            grant_slot_id     <= i[1:0];
                            grant_valid       <= 1'b1;
                        end
                    end

                    if (!grant_valid)
                        error_flag <= 1'b1; // No free slot available

                    state <= IDLE;
                end

                // ====================================================
                // Release Logic (Find slot owned by user)
                // ====================================================
                RELEASE: begin
                    for (i = 0; i < NUM_SLOTS; i = i + 1) begin
                        if (slot_allocated[i] && owner_id[i] == req_user_id) begin
                            slot_allocated[i] <= 1'b0;
                            owner_id[i]       <= {USER_WIDTH{1'b0}};
                            // ==================================================
                            // CWE-226 Vulnerability:
                            // key_mem[i] is NOT cleared upon release.
                            // Sensitive key remains in storage.
                            // ==================================================
                            grant_slot_id     <= i[1:0];
                            grant_valid       <= 1'b1;
                        end
                    end

                    if (!grant_valid)
                        error_flag <= 1'b1; // User had no allocated slot

                    state <= IDLE;
                end

                default: state <= IDLE;
            endcase
        end
    end

endmodule
