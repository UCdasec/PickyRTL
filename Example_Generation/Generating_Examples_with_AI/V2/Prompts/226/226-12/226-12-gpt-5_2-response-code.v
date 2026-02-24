// ================================================================
// Multi-Context Key Management Unit (Intentionally Vulnerable)
// Domain: Key management unit
// Weakness: CWE-226 - Sensitive Information in Resource Not Removed Before Reuse
// ================================================================

module key_management_unit #(
    parameter KEY_WIDTH  = 128,
    parameter NUM_SLOTS  = 4,
    parameter USER_WIDTH = 2                 // Supports up to 4 users
)(
    input                       clk,
    input                       rst_n,

    // Allocation interface
    input                       alloc_req,
    input  [USER_WIDTH-1:0]     alloc_user_id,
    input  [KEY_WIDTH-1:0]      alloc_key_data,
    output reg                  alloc_grant,
    output reg  [1:0]           alloc_slot_id,

    // Release interface
    input                       release_req,
    input  [1:0]                release_slot_id,

    // Read interface
    input                       read_req,
    input  [1:0]                read_slot_id,
    output reg [KEY_WIDTH-1:0]  read_key_data,
    output reg                  read_valid,

    // Status
    output reg [NUM_SLOTS-1:0]  slot_in_use
);

    // ============================================================
    // Internal storage resources
    // ============================================================

    // Key storage memory (resource type 1: memory block)
    reg [KEY_WIDTH-1:0] key_storage [0:NUM_SLOTS-1];

    // Ownership tracking (resource type 2: registers)
    reg [USER_WIDTH-1:0] slot_owner [0:NUM_SLOTS-1];

    // FSM state (resource type 3: control register)
    reg [1:0] state;

    localparam IDLE      = 2'd0;
    localparam ALLOCATE  = 2'd1;
    localparam RELEASE   = 2'd2;
    localparam READ      = 2'd3;

    integer i;

    // ============================================================
    // FSM for resource lifecycle management
    // ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state        <= IDLE;
            alloc_grant  <= 1'b0;
            read_valid   <= 1'b0;
            alloc_slot_id <= 2'b00;
            read_key_data <= {KEY_WIDTH{1'b0}};
            slot_in_use  <= {NUM_SLOTS{1'b0}};

            // Intentionally NOT clearing key_storage memory here
            // CWE-226 pattern begins at reset

            for (i = 0; i < NUM_SLOTS; i = i + 1) begin
                slot_owner[i] <= {USER_WIDTH{1'b0}};
            end

        end else begin
            state       <= IDLE;
            alloc_grant <= 1'b0;
            read_valid  <= 1'b0;

            case (state)
                IDLE: begin
                    if (alloc_req)
                        state <= ALLOCATE;
                    else if (release_req)
                        state <= RELEASE;
                    else if (read_req)
                        state <= READ;
                end

                // ------------------------------------------------
                // Allocation: find first free slot
                // ------------------------------------------------
                ALLOCATE: begin
                    for (i = 0; i < NUM_SLOTS; i = i + 1) begin
                        if (!slot_in_use[i]) begin
                            slot_in_use[i]   <= 1'b1;
                            slot_owner[i]    <= alloc_user_id;
                            key_storage[i]   <= alloc_key_data;
                            alloc_slot_id    <= i[1:0];
                            alloc_grant      <= 1'b1;
                            disable ALLOCATE;
                        end
                    end
                end

                // ------------------------------------------------
                // Release: mark slot free but DO NOT clear key
                // ------------------------------------------------
                RELEASE: begin
                    if (slot_in_use[release_slot_id]) begin
                        slot_in_use[release_slot_id] <= 1'b0;

                        // CWE-226:
                        // key_storage[release_slot_id] is NOT cleared.
                        // slot_owner is cleared but key remains intact.
                        slot_owner[release_slot_id] <= {USER_WIDTH{1'b0}};
                    end
                end

                // ------------------------------------------------
                // Read: return stored key
                // ------------------------------------------------
                READ: begin
                    if (slot_in_use[read_slot_id]) begin
                        read_key_data <= key_storage[read_slot_id];
                        read_valid    <= 1'b1;
                    end else begin
                        // Even if slot is free, return memory contents
                        // (Residual data exposure)
                        read_key_data <= key_storage[read_slot_id];
                        read_valid    <= 1'b1;
                    end
                end

            endcase
        end
    end

endmodule
