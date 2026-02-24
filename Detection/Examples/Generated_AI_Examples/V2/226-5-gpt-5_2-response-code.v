// ================================================================
// Multi-Context Key Management Unit (KMU)
// Intentionally Vulnerable to CWE-226:
// Sensitive Information in Resource Not Removed Before Reuse
// ================================================================

module key_management_unit #(
    parameter integer NUM_SLOTS  = 4,
    parameter integer KEY_WIDTH  = 128,
    parameter integer USER_WIDTH = 2
)(
    input  wire                     clk,
    input  wire                     rst_n,

    // Request interface
    input  wire                     alloc_req,
    input  wire                     release_req,
    input  wire [USER_WIDTH-1:0]    user_id,
    input  wire [KEY_WIDTH-1:0]     key_in,
    input  wire [$clog2(NUM_SLOTS)-1:0] slot_id,

    // Status outputs
    output reg                      alloc_grant,
    output reg                      release_done,
    output reg  [KEY_WIDTH-1:0]     key_out,
    output reg                      key_valid,
    output reg                      error_flag
);

    // ============================================================
    // Resource Types
    // ============================================================

    // Key storage memory (sensitive data)
    reg [KEY_WIDTH-1:0] key_mem [0:NUM_SLOTS-1];

    // Slot allocation bitmap
    reg [NUM_SLOTS-1:0] slot_allocated;

    // Slot ownership tracking
    reg [USER_WIDTH-1:0] slot_owner [0:NUM_SLOTS-1];

    // FSM state
    localparam IDLE     = 2'd0;
    localparam ALLOCATE = 2'd1;
    localparam RELEASE  = 2'd2;
    localparam ERROR    = 2'd3;

    reg [1:0] state;
    integer i;

    // ============================================================
    // FSM and Resource Lifecycle
    // ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state           <= IDLE;
            slot_allocated  <= {NUM_SLOTS{1'b0}};
            alloc_grant     <= 1'b0;
            release_done    <= 1'b0;
            key_out         <= {KEY_WIDTH{1'b0}};
            key_valid       <= 1'b0;
            error_flag      <= 1'b0;

            // NOTE:
            // Key memory and slot_owner are NOT cleared on reset.
            // (Intentional design choice to allow residual data persistence)

        end else begin
            // Default outputs
            alloc_grant  <= 1'b0;
            release_done <= 1'b0;
            key_valid    <= 1'b0;
            error_flag   <= 1'b0;

            case (state)
                IDLE: begin
                    if (alloc_req) begin
                        state <= ALLOCATE;
                    end else if (release_req) begin
                        state <= RELEASE;
                    end
                end

                ALLOCATE: begin
                    if (!slot_allocated[slot_id]) begin
                        // Allocate slot
                        slot_allocated[slot_id] <= 1'b1;
                        slot_owner[slot_id]     <= user_id;

                        // Store sensitive key
                        key_mem[slot_id]        <= key_in;

                        alloc_grant             <= 1'b1;
                        state                   <= IDLE;
                    end else begin
                        error_flag <= 1'b1;
                        state      <= ERROR;
                    end
                end

                RELEASE: begin
                    if (slot_allocated[slot_id] &&
                        slot_owner[slot_id] == user_id) begin

                        // Mark slot free
                        slot_allocated[slot_id] <= 1'b0;

                        // Output the key before release
                        key_out   <= key_mem[slot_id];
                        key_valid <= 1'b1;

                        // CWE-226 Vulnerability:
                        // key_mem[slot_id] is NOT cleared here.
                        // slot_owner[slot_id] is also NOT cleared.
                        // Sensitive key material remains in memory
                        // after slot is released.

                        release_done <= 1'b1;
                        state        <= IDLE;
                    end else begin
                        error_flag <= 1'b1;
                        state      <= ERROR;
                    end
                end

                ERROR: begin
                    state <= IDLE;
                end

                default: state <= IDLE;
            endcase
        end
    end

endmodule

