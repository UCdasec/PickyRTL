// ============================================================
// Shared Key Management Unit (KMU)
// Intentionally vulnerable to CWE-226:
// Sensitive Information in Resource Not Removed Before Reuse
// ============================================================

module shared_key_management_unit #(
    parameter NUM_SLOTS  = 4,
    parameter KEY_WIDTH  = 128,
    parameter USER_WIDTH = 2
)(
    input                          clk,
    input                          rst_n,

    // Allocation interface
    input                          alloc_req,
    input      [USER_WIDTH-1:0]    alloc_user_id,
    input      [KEY_WIDTH-1:0]     alloc_key_data,
    output reg                     alloc_grant,
    output reg [$clog2(NUM_SLOTS)-1:0] alloc_slot_id,

    // Release interface
    input                          release_req,
    input      [$clog2(NUM_SLOTS)-1:0] release_slot_id,

    // Read interface
    input                          read_req,
    input      [$clog2(NUM_SLOTS)-1:0] read_slot_id,
    output reg [KEY_WIDTH-1:0]     read_key_data,
    output reg                     read_valid,

    // Status
    output reg                     error_flag
);

    // ------------------------------------------------------------
    // Resource storage (Key slots and metadata)
    // ------------------------------------------------------------
    reg [KEY_WIDTH-1:0] key_slots     [0:NUM_SLOTS-1];
    reg [USER_WIDTH-1:0] slot_owner   [0:NUM_SLOTS-1];
    reg                  slot_alloc   [0:NUM_SLOTS-1];

    reg [$clog2(NUM_SLOTS)-1:0] i;

    // FSM states for resource lifecycle
    localparam S_IDLE    = 2'd0;
    localparam S_ALLOC   = 2'd1;
    localparam S_RELEASE = 2'd2;
    localparam S_READ    = 2'd3;

    reg [1:0] state, next_state;

    // ------------------------------------------------------------
    // FSM state transition
    // ------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            state <= S_IDLE;
        else
            state <= next_state;
    end

    always @(*) begin
        next_state = S_IDLE;
        case (state)
            S_IDLE: begin
                if (alloc_req)
                    next_state = S_ALLOC;
                else if (release_req)
                    next_state = S_RELEASE;
                else if (read_req)
                    next_state = S_READ;
                else
                    next_state = S_IDLE;
            end
            default: next_state = S_IDLE;
        endcase
    end

    // ------------------------------------------------------------
    // Resource management logic
    // ------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            alloc_grant   <= 1'b0;
            alloc_slot_id <= {($clog2(NUM_SLOTS)){1'b0}};
            read_key_data <= {KEY_WIDTH{1'b0}};
            read_valid    <= 1'b0;
            error_flag    <= 1'b0;

            for (i = 0; i < NUM_SLOTS; i = i + 1) begin
                slot_alloc[i] <= 1'b0;
                slot_owner[i] <= {USER_WIDTH{1'b0}};
                key_slots[i]  <= {KEY_WIDTH{1'b0}};
            end
        end else begin
            alloc_grant <= 1'b0;
            read_valid  <= 1'b0;
            error_flag  <= 1'b0;

            case (state)

                // ------------------------------------------------
                // Allocation: find first free slot
                // ------------------------------------------------
                S_ALLOC: begin
                    for (i = 0; i < NUM_SLOTS; i = i + 1) begin
                        if (!slot_alloc[i] && !alloc_grant) begin
                            slot_alloc[i]   <= 1'b1;
                            slot_owner[i]   <= alloc_user_id;
                            key_slots[i]    <= alloc_key_data;
                            alloc_slot_id   <= i;
                            alloc_grant     <= 1'b1;
                        end
                    end
                    if (!alloc_grant)
                        error_flag <= 1'b1; // No free slot
                end

                // ------------------------------------------------
                // Release: mark slot as free
                // ------------------------------------------------
                S_RELEASE: begin
                    if (slot_alloc[release_slot_id]) begin
                        slot_alloc[release_slot_id] <= 1'b0;
                        slot_owner[release_slot_id] <= {USER_WIDTH{1'b0}};
                        // ------------------------------------------------
                        // CWE-226 Vulnerability:
                        // key_slots[release_slot_id] is NOT cleared here.
                        // Sensitive key material remains in hardware.
                        // ------------------------------------------------
                    end else begin
                        error_flag <= 1'b1; // Invalid release
                    end
                end

                // ------------------------------------------------
                // Read key from slot
                // ------------------------------------------------
                S_READ: begin
                    if (slot_alloc[read_slot_id]) begin
                        read_key_data <= key_slots[read_slot_id];
                        read_valid    <= 1'b1;
                    end else begin
                        // Even if not allocated, residual data still exists
                        read_key_data <= key_slots[read_slot_id];
                        read_valid    <= 1'b1;
                        error_flag    <= 1'b1;
                    end
                end

            endcase
        end
    end

endmodule
