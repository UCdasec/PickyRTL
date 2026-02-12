// Shared Cryptographic Accelerator with Intentional CWE-226 Weakness
// Domain: Shared cryptographic accelerator
// Weakness: Sensitive key material and intermediate results are not cleared
//           when a context is released and later reallocated.

module shared_crypto_accel #(
    parameter DATA_WIDTH = 128,
    parameter NUM_CONTEXTS = 4
)(
    input  wire                     clk,
    input  wire                     rst_n,

    // Allocation interface
    input  wire                     alloc_req,
    input  wire [1:0]               alloc_user_id,
    output reg                      alloc_grant,
    output reg  [1:0]               alloc_context_id,

    // Crypto operation interface
    input  wire                     start,
    input  wire [1:0]               context_id,
    input  wire [DATA_WIDTH-1:0]    key_in,
    input  wire [DATA_WIDTH-1:0]    data_in,
    input  wire                     release,

    output reg                      done,
    output reg  [DATA_WIDTH-1:0]    data_out,
    output reg                      busy
);

    // ============================================================
    // Resource Types:
    // - key_storage      : stores sensitive keys per context
    // - data_storage     : stores input data per context
    // - result_storage   : stores intermediate results
    // - owner_id         : tracks owning user
    // - context_state    : FSM per context (IDLE, ALLOCATED, IN_USE)
    // ============================================================

    localparam STATE_IDLE      = 2'b00;
    localparam STATE_ALLOCATED = 2'b01;
    localparam STATE_IN_USE    = 2'b10;

    reg [DATA_WIDTH-1:0] key_storage     [0:NUM_CONTEXTS-1];
    reg [DATA_WIDTH-1:0] data_storage    [0:NUM_CONTEXTS-1];
    reg [DATA_WIDTH-1:0] result_storage  [0:NUM_CONTEXTS-1];

    reg [1:0] owner_id       [0:NUM_CONTEXTS-1];
    reg [1:0] context_state  [0:NUM_CONTEXTS-1];

    integer i;

    // Allocation logic with simple priority arbitration
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            alloc_grant      <= 1'b0;
            alloc_context_id <= 2'b00;
            for (i = 0; i < NUM_CONTEXTS; i = i + 1) begin
                context_state[i] <= STATE_IDLE;
                owner_id[i]      <= 2'b00;
            end
        end else begin
            alloc_grant <= 1'b0;

            if (alloc_req) begin
                for (i = 0; i < NUM_CONTEXTS; i = i + 1) begin
                    if (context_state[i] == STATE_IDLE && !alloc_grant) begin
                        context_state[i] <= STATE_ALLOCATED;
                        owner_id[i]      <= alloc_user_id;
                        alloc_context_id <= i[1:0];
                        alloc_grant      <= 1'b1;
                    end
                end
            end
        end
    end

    // Crypto operation state handling
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            done <= 1'b0;
            busy <= 1'b0;
            data_out <= {DATA_WIDTH{1'b0}};
        end else begin
            done <= 1'b0;

            // Start crypto operation
            if (start && context_state[context_id] == STATE_ALLOCATED) begin
                context_state[context_id] <= STATE_IN_USE;
                busy <= 1'b1;

                // Store sensitive key and data
                key_storage[context_id]  <= key_in;
                data_storage[context_id] <= data_in;

                // Simple example "crypto" operation (XOR-based)
                result_storage[context_id] <= key_in ^ data_in;
            end

            // Complete operation in next cycle
            if (context_state[context_id] == STATE_IN_USE) begin
                data_out <= result_storage[context_id];
                done <= 1'b1;
                busy <= 1'b0;
                context_state[context_id] <= STATE_ALLOCATED;
            end

            // Release context (CWE-226 weakness: no clearing of key/data/result)
            if (release && context_state[context_id] == STATE_ALLOCATED) begin
                context_state[context_id] <= STATE_IDLE;

                // Ownership removed
                owner_id[context_id] <= 2'b00;

                // INTENTIONAL CWE-226:
                // key_storage, data_storage, and result_storage
                // are NOT cleared here before context becomes IDLE.
            end
        end
    end

endmodule
