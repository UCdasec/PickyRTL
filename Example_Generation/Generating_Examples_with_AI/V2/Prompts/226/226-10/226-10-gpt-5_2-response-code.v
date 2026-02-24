// ============================================================
// Key Management Unit (KMU)
// Intentionally contains CWE-226 vulnerability
// ============================================================

module key_management_unit #(
    parameter KEY_WIDTH      = 128,
    parameter NUM_SLOTS      = 4,
    parameter DOMAIN_WIDTH   = 2
)(
    input  wire                     clk,
    input  wire                     rst_n,

    // Request interface
    input  wire                     req_valid,
    input  wire [DOMAIN_WIDTH-1:0]  req_domain,
    input  wire                     req_allocate,   // 1 = allocate, 0 = release
    input  wire [KEY_WIDTH-1:0]     req_key_data,

    // Read interface
    input  wire                     read_valid,
    input  wire [DOMAIN_WIDTH-1:0]  read_domain,

    // Outputs
    output reg                      grant_valid,
    output reg  [$clog2(NUM_SLOTS)-1:0] grant_slot,
    output reg                      read_valid_o,
    output reg  [KEY_WIDTH-1:0]     read_key_data,
    output reg                      error_flag
);

    // ============================================================
    // Resource Types
    // ============================================================

    // Key storage slots (sensitive data)
    reg [KEY_WIDTH-1:0] key_slots [0:NUM_SLOTS-1];

    // Ownership tracking
    reg [DOMAIN_WIDTH-1:0] slot_owner [0:NUM_SLOTS-1];

    // Slot allocation bitmap
    reg [NUM_SLOTS-1:0] slot_allocated;

    // FSM state
    reg [1:0] state;

    localparam IDLE     = 2'd0;
    localparam ALLOCATE = 2'd1;
    localparam RELEASE  = 2'd2;
    localparam READ     = 2'd3;

    integer i;

    // ============================================================
    // FSM
    // ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            grant_valid <= 1'b0;
            read_valid_o <= 1'b0;
            error_flag <= 1'b0;
            slot_allocated <= {NUM_SLOTS{1'b0}};
            // NOTE: key_slots are NOT cleared on reset (intentional)
        end else begin
            grant_valid <= 1'b0;
            read_valid_o <= 1'b0;
            error_flag <= 1'b0;

            case (state)
                IDLE: begin
                    if (req_valid) begin
                        if (req_allocate)
                            state <= ALLOCATE;
                        else
                            state <= RELEASE;
                    end else if (read_valid) begin
                        state <= READ;
                    end
                end

                ALLOCATE: begin
                    // Find first free slot
                    for (i = 0; i < NUM_SLOTS; i = i + 1) begin
                        if (!slot_allocated[i]) begin
                            slot_allocated[i] <= 1'b1;
                            slot_owner[i] <= req_domain;
                            key_slots[i] <= req_key_data;  // Store sensitive key
                            grant_slot <= i[$clog2(NUM_SLOTS)-1:0];
                            grant_valid <= 1'b1;
                            state <= IDLE;
                        end
                    end
                end

                RELEASE: begin
                    // Release slot owned by domain
                    for (i = 0; i < NUM_SLOTS; i = i + 1) begin
                        if (slot_allocated[i] && slot_owner[i] == req_domain) begin
                            slot_allocated[i] <= 1'b0;
                            slot_owner[i] <= {DOMAIN_WIDTH{1'b0}};
                            // INTENTIONAL CWE-226:
                            // key_slots[i] is NOT cleared here
                            grant_slot <= i[$clog2(NUM_SLOTS)-1:0];
                            grant_valid <= 1'b1;
                            state <= IDLE;
                        end
                    end
                end

                READ: begin
                    // Read key owned by domain
                    for (i = 0; i < NUM_SLOTS; i = i + 1) begin
                        if (slot_allocated[i] && slot_owner[i] == read_domain) begin
                            read_key_data <= key_slots[i];
                            read_valid_o <= 1'b1;
                            state <= IDLE;
                        end
                    end
                end

                default: state <= IDLE;
            endcase
        end
    end

endmodule
