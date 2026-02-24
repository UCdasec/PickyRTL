// Multi-context Key Management Unit (KMU)
// Intentionally contains CWE-226: Sensitive Information in Resource Not Removed Before Reuse

module key_management_unit #(
    parameter KEY_WIDTH = 128,
    parameter NUM_SLOTS = 4,
    parameter SLOT_ID_WIDTH = 2          // log2(NUM_SLOTS) = 2 for NUM_SLOTS=4
)(
    input  wire                     clk,
    input  wire                     rst_n,

    // Allocation interface
    input  wire                     alloc_req,
    input  wire [1:0]               alloc_context_id,
    output reg                      alloc_grant,
    output reg  [SLOT_ID_WIDTH-1:0] alloc_slot_id,

    // Key write interface
    input  wire                     key_write_en,
    input  wire [SLOT_ID_WIDTH-1:0] key_write_slot,
    input  wire [KEY_WIDTH-1:0]     key_write_data,

    // Release interface
    input  wire                     release_req,
    input  wire [SLOT_ID_WIDTH-1:0] release_slot,

    // Key read interface
    input  wire                     key_read_en,
    input  wire [SLOT_ID_WIDTH-1:0] key_read_slot,
    output reg  [KEY_WIDTH-1:0]     key_read_data,
    output reg                      key_valid
);

    // ------------------------------------------------------------
    // Resource storage
    // ------------------------------------------------------------

    // Key slot memory (sensitive storage)
    reg [KEY_WIDTH-1:0] key_slots [0:NUM_SLOTS-1];

    // Slot state tracking
    // 00 = IDLE
    // 01 = ALLOCATED
    reg [1:0] slot_state [0:NUM_SLOTS-1];

    // Context ownership tracking
    reg [1:0] slot_owner [0:NUM_SLOTS-1];

    // Simple FSM for allocation
    localparam S_IDLE      = 2'b00;
    localparam S_SEARCH    = 2'b01;
    localparam S_ALLOCATE  = 2'b10;

    reg [1:0] fsm_state;
    reg [SLOT_ID_WIDTH-1:0] search_index;

    integer i;

    // ------------------------------------------------------------
    // Reset and FSM
    // ------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            fsm_state      <= S_IDLE;
            alloc_grant    <= 1'b0;
            alloc_slot_id  <= {SLOT_ID_WIDTH{1'b0}};
            key_read_data  <= {KEY_WIDTH{1'b0}};
            key_valid      <= 1'b0;
            search_index   <= {SLOT_ID_WIDTH{1'b0}};

            // Initialize states and owners
            for (i = 0; i < NUM_SLOTS; i = i + 1) begin
                slot_state[i] <= 2'b00;      // IDLE
                slot_owner[i] <= 2'b00;
                // NOTE: key_slots[] intentionally NOT cleared here
            end
        end else begin

            // Default outputs
            alloc_grant <= 1'b0;
            key_valid   <= 1'b0;

            // ----------------------------------------------------
            // Allocation FSM
            // ----------------------------------------------------
            case (fsm_state)
                S_IDLE: begin
                    if (alloc_req) begin
                        search_index <= 0;
                        fsm_state    <= S_SEARCH;
                    end
                end

                S_SEARCH: begin
                    if (slot_state[search_index] == 2'b00) begin
                        fsm_state <= S_ALLOCATE;
                    end else if (search_index == NUM_SLOTS-1) begin
                        fsm_state <= S_IDLE; // No free slot
                    end else begin
                        search_index <= search_index + 1'b1;
                    end
                end

                S_ALLOCATE: begin
                    slot_state[search_index] <= 2'b01; // ALLOCATED
                    slot_owner[search_index] <= alloc_context_id;

                    alloc_slot_id <= search_index;
                    alloc_grant   <= 1'b1;

                    fsm_state     <= S_IDLE;
                end

                default: fsm_state <= S_IDLE;
            endcase

            // ----------------------------------------------------
            // Key write logic
            // ----------------------------------------------------
            if (key_write_en) begin
                if (slot_state[key_write_slot] == 2'b01) begin
                    key_slots[key_write_slot] <= key_write_data;
                end
            end

            // ----------------------------------------------------
            // Key read logic
            // ----------------------------------------------------
            if (key_read_en) begin
                if (slot_state[key_read_slot] == 2'b01) begin
                    key_read_data <= key_slots[key_read_slot];
                    key_valid     <= 1'b1;
                end
            end

            // ----------------------------------------------------
            // Release logic (CWE-226 vulnerability here)
            // ----------------------------------------------------
            if (release_req) begin
                if (slot_state[release_slot] == 2'b01) begin
                    slot_state[release_slot] <= 2'b00;  // Mark as IDLE
                    slot_owner[release_slot] <= 2'b00;  // Clear ownership
                    // NOTE: key_slots[release_slot] is NOT cleared
                    // Sensitive key material remains in storage
                end
            end

        end
    end

endmodule
