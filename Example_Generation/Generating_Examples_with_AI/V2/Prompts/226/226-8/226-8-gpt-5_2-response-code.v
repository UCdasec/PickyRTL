// Multi-context Key Management Unit
// Intentionally vulnerable to CWE-226: Sensitive Information in Resource Not Removed Before Reuse

module key_management_unit #(
    parameter NUM_SLOTS  = 4,
    parameter KEY_WIDTH  = 128,
    parameter USER_WIDTH = 4
)(
    input                         clk,
    input                         rst_n,

    // Allocation interface
    input                         alloc_req,
    input      [USER_WIDTH-1:0]   alloc_user_id,
    input      [KEY_WIDTH-1:0]    alloc_key_data,
    output reg                    alloc_grant,
    output reg [$clog2(NUM_SLOTS)-1:0] alloc_slot_id,

    // Release interface
    input                         release_req,
    input      [$clog2(NUM_SLOTS)-1:0] release_slot_id,

    // Read interface
    input                         read_req,
    input      [$clog2(NUM_SLOTS)-1:0] read_slot_id,
    output reg [KEY_WIDTH-1:0]    read_key_data,
    output reg                    read_valid,

    // Status
    output reg [NUM_SLOTS-1:0]    slot_allocated
);

    // ------------------------------------------------------------
    // Internal resources
    // ------------------------------------------------------------

    // Key storage (sensitive information)
    reg [KEY_WIDTH-1:0] key_mem [0:NUM_SLOTS-1];

    // Ownership tracking
    reg [USER_WIDTH-1:0] owner_id [0:NUM_SLOTS-1];

    // Simple FSM states
    localparam STATE_IDLE     = 2'd0;
    localparam STATE_ALLOCATE = 2'd1;
    localparam STATE_RELEASE  = 2'd2;

    reg [1:0] state, next_state;

    integer i;

    // ------------------------------------------------------------
    // FSM - Sequential
    // ------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= STATE_IDLE;
        end else begin
            state <= next_state;
        end
    end

    // ------------------------------------------------------------
    // FSM - Combinational
    // ------------------------------------------------------------
    always @(*) begin
        next_state = state;
        case (state)
            STATE_IDLE: begin
                if (alloc_req)
                    next_state = STATE_ALLOCATE;
                else if (release_req)
                    next_state = STATE_RELEASE;
            end

            STATE_ALLOCATE: begin
                next_state = STATE_IDLE;
            end

            STATE_RELEASE: begin
                next_state = STATE_IDLE;
            end

            default: next_state = STATE_IDLE;
        endcase
    end

    // ------------------------------------------------------------
    // Allocation, Release, and Read Logic
    // ------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            alloc_grant     <= 1'b0;
            alloc_slot_id   <= {($clog2(NUM_SLOTS)){1'b0}};
            read_key_data   <= {KEY_WIDTH{1'b0}};
            read_valid      <= 1'b0;
            slot_allocated  <= {NUM_SLOTS{1'b0}};

            for (i = 0; i < NUM_SLOTS; i = i + 1) begin
                key_mem[i]  <= {KEY_WIDTH{1'b0}};
                owner_id[i] <= {USER_WIDTH{1'b0}};
            end
        end else begin
            alloc_grant <= 1'b0;
            read_valid  <= 1'b0;

            case (state)

                // ------------------------------------------------
                // Allocate first free slot
                // ------------------------------------------------
                STATE_ALLOCATE: begin
                    for (i = 0; i < NUM_SLOTS; i = i + 1) begin
                        if (!slot_allocated[i] && !alloc_grant) begin
                            slot_allocated[i] <= 1'b1;
                            key_mem[i]        <= alloc_key_data;   // store sensitive key
                            owner_id[i]       <= alloc_user_id;
                            alloc_slot_id     <= i[$clog2(NUM_SLOTS)-1:0];
                            alloc_grant       <= 1'b1;
                        end
                    end
                end

                // ------------------------------------------------
                // Release slot (CWE-226 vulnerability here)
                // ------------------------------------------------
                STATE_RELEASE: begin
                    if (slot_allocated[release_slot_id]) begin
                        slot_allocated[release_slot_id] <= 1'b0;
                        // Vulnerability: key_mem and owner_id are NOT cleared
                        // Sensitive key data remains in key_mem
                    end
                end

            endcase

            // ----------------------------------------------------
            // Read logic (no ownership enforcement)
            // ----------------------------------------------------
            if (read_req) begin
                read_key_data <= key_mem[read_slot_id];
                read_valid    <= 1'b1;
            end
        end
    end

endmodule
