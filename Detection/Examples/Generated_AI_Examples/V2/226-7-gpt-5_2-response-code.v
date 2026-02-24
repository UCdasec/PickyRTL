// Multi-context Key Management Unit
// Intentionally contains CWE-226: Sensitive information not cleared before reuse

module key_management_unit #(
    parameter KEY_WIDTH  = 128,
    parameter NUM_SLOTS  = 4,
    parameter USER_WIDTH = 2              // Supports up to 4 users
)(
    input                       clk,
    input                       rst_n,

    // Allocation interface
    input                       alloc_req,
    input  [USER_WIDTH-1:0]     alloc_user_id,
    output reg                  alloc_grant,
    output reg [$clog2(NUM_SLOTS)-1:0] alloc_slot_id,

    // Write key interface
    input                       write_req,
    input  [$clog2(NUM_SLOTS)-1:0] write_slot_id,
    input  [KEY_WIDTH-1:0]      write_key,
    input  [USER_WIDTH-1:0]     write_user_id,
    output reg                  write_done,

    // Read key interface
    input                       read_req,
    input  [$clog2(NUM_SLOTS)-1:0] read_slot_id,
    input  [USER_WIDTH-1:0]     read_user_id,
    output reg [KEY_WIDTH-1:0]  read_key,
    output reg                  read_valid,

    // Release interface
    input                       release_req,
    input  [$clog2(NUM_SLOTS)-1:0] release_slot_id,
    input  [USER_WIDTH-1:0]     release_user_id,
    output reg                  release_done
);

    // -----------------------------
    // Resource Storage (Key Slots)
    // -----------------------------
    reg [KEY_WIDTH-1:0] key_slots [0:NUM_SLOTS-1];   // Sensitive key storage
    reg                 slot_valid [0:NUM_SLOTS-1];  // Allocation state
    reg [USER_WIDTH-1:0] slot_owner [0:NUM_SLOTS-1]; // Ownership tracking

    integer i;

    // Simple FSM states
    localparam IDLE     = 2'd0;
    localparam ALLOCATE = 2'd1;
    localparam RELEASE  = 2'd2;

    reg [1:0] state;

    // -----------------------------
    // Sequential Logic
    // -----------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state        <= IDLE;
            alloc_grant  <= 1'b0;
            write_done   <= 1'b0;
            read_valid   <= 1'b0;
            release_done <= 1'b0;

            for (i = 0; i < NUM_SLOTS; i = i + 1) begin
                slot_valid[i] <= 1'b0;
                slot_owner[i] <= {USER_WIDTH{1'b0}};
                // NOTE: key_slots are NOT cleared on reset (intentional)
            end
        end else begin
            // Default outputs
            alloc_grant  <= 1'b0;
            write_done   <= 1'b0;
            read_valid   <= 1'b0;
            release_done <= 1'b0;

            case (state)
                IDLE: begin
                    if (alloc_req) begin
                        state <= ALLOCATE;
                    end else if (release_req) begin
                        state <= RELEASE;
                    end else begin
                        state <= IDLE;
                    end

                    // Write operation
                    if (write_req && slot_valid[write_slot_id] &&
                        slot_owner[write_slot_id] == write_user_id) begin
                        key_slots[write_slot_id] <= write_key;
                        write_done <= 1'b1;
                    end

                    // Read operation
                    if (read_req && slot_valid[read_slot_id] &&
                        slot_owner[read_slot_id] == read_user_id) begin
                        read_key   <= key_slots[read_slot_id];
                        read_valid <= 1'b1;
                    end
                end

                ALLOCATE: begin
                    // Find first free slot
                    for (i = 0; i < NUM_SLOTS; i = i + 1) begin
                        if (!slot_valid[i]) begin
                            slot_valid[i] <= 1'b1;
                            slot_owner[i] <= alloc_user_id;
                            alloc_slot_id <= i[$clog2(NUM_SLOTS)-1:0];
                            alloc_grant   <= 1'b1;
                            state         <= IDLE;
                        end
                    end
                end

                RELEASE: begin
                    if (slot_valid[release_slot_id] &&
                        slot_owner[release_slot_id] == release_user_id) begin
                        slot_valid[release_slot_id] <= 1'b0;
                        slot_owner[release_slot_id] <= {USER_WIDTH{1'b0}};
                        // NOTE: key_slots[release_slot_id] is NOT cleared (intentional CWE-226)
                        release_done <= 1'b1;
                    end
                    state <= IDLE;
                end

                default: state <= IDLE;
            endcase
        end
    end

endmodule
