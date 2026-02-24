`timescale 1ns / 1ps

module key_management_unit #(
    parameter KEY_WIDTH  = 128,
    parameter NUM_SLOTS  = 4
)(
    input  wire                     clk,
    input  wire                     rst_n,

    // Allocation interface
    input  wire                     alloc_req,
    input  wire [1:0]               alloc_domain_id,
    input  wire [KEY_WIDTH-1:0]     alloc_key_data,
    output reg                      alloc_grant,
    output reg  [1:0]               alloc_slot_id,

    // Release interface
    input  wire                     release_req,
    input  wire [1:0]               release_slot_id,

    // Read interface
    input  wire                     read_req,
    input  wire [1:0]               read_slot_id,
    output reg  [KEY_WIDTH-1:0]     read_key_data,
    output reg                      read_valid,

    // Status
    output reg  [NUM_SLOTS-1:0]     slot_in_use
);

    // ------------------------------------------------------------
    // Resource Storage (Key Slots)
    // ------------------------------------------------------------
    reg [KEY_WIDTH-1:0] key_storage [0:NUM_SLOTS-1];
    reg [1:0]           slot_owner  [0:NUM_SLOTS-1];  // domain ownership tracking

    // FSM states
    localparam IDLE      = 2'd0;
    localparam ALLOCATE  = 2'd1;
    localparam RELEASE   = 2'd2;
    localparam READ      = 2'd3;

    reg [1:0] state;
    reg [1:0] next_state;

    integer i;

    // ------------------------------------------------------------
    // Next-State Logic
    // ------------------------------------------------------------
    always @(*) begin
        next_state = IDLE;
        case (state)
            IDLE: begin
                if (alloc_req)
                    next_state = ALLOCATE;
                else if (release_req)
                    next_state = RELEASE;
                else if (read_req)
                    next_state = READ;
                else
                    next_state = IDLE;
            end
            default: next_state = IDLE;
        endcase
    end

    // ------------------------------------------------------------
    // State Register
    // ------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            state <= IDLE;
        else
            state <= next_state;
    end

    // ------------------------------------------------------------
    // Main Control Logic
    // ------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            alloc_grant     <= 1'b0;
            alloc_slot_id   <= 2'd0;
            read_key_data   <= {KEY_WIDTH{1'b0}};
            read_valid      <= 1'b0;
            slot_in_use     <= {NUM_SLOTS{1'b0}};
            for (i = 0; i < NUM_SLOTS; i = i + 1) begin
                key_storage[i] <= {KEY_WIDTH{1'b0}};
                slot_owner[i]  <= 2'd0;
            end
        end else begin
            alloc_grant <= 1'b0;
            read_valid  <= 1'b0;

            case (state)
                ALLOCATE: begin
                    // Simple first-fit allocation
                    for (i = 0; i < NUM_SLOTS; i = i + 1) begin
                        if (!slot_in_use[i]) begin
                            key_storage[i] <= alloc_key_data;
                            slot_owner[i]  <= alloc_domain_id;
                            slot_in_use[i] <= 1'b1;

                            alloc_grant   <= 1'b1;
                            alloc_slot_id <= i[1:0];
                        end
                    end
                end

                RELEASE: begin
                    // Mark slot as free but DO NOT clear key_storage
                    if (slot_in_use[release_slot_id]) begin
                        slot_in_use[release_slot_id] <= 1'b0;
                        slot_owner[release_slot_id]  <= 2'd0;
                        // CWE-226: key_storage is NOT cleared here
                    end
                end

                READ: begin
                    if (slot_in_use[read_slot_id]) begin
                        read_key_data <= key_storage[read_slot_id];
                        read_valid    <= 1'b1;
                    end else begin
                        // Even if slot is not in use, data may still exist
                        read_key_data <= key_storage[read_slot_id];
                        read_valid    <= 1'b1;
                    end
                end

                default: ;
            endcase
        end
    end

endmodule
