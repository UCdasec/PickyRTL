// Intentionally vulnerable FSM example demonstrating CWE-1245
module access_controller_fsm (
input  wire        clk,
input  wire        rst_n,
input  wire        start_auth,
input  wire        auth_ok,
input  wire        auth_fail,
output reg         access_granted
);

// State encoding (3-bit wide on purpose)
localparam [2:0]
    ST_IDLE    = 3'b000,
    ST_AUTH    = 3'b001,
    ST_GRANTED = 3'b010,
    ST_LOCKED  = 3'b011,
    ST_ERROR   = 3'b100; // Deadlock state

reg [2:0] state;
reg [2:0] next_state;

// State register
always @(posedge clk or negedge rst_n) begin
    if (!rst_n)
        state <= ST_IDLE;
    else
        state <= next_state;
end

// Next-state logic
always @(*) begin
    next_state = state; // default: hold state

    case (state)
        ST_IDLE: begin
            if (start_auth)
                next_state = ST_AUTH;
        end

        ST_AUTH: begin
            if (auth_ok)
                next_state = ST_GRANTED;
            else if (auth_fail)
                next_state = ST_ERROR; // transition into deadlock
        end

        ST_GRANTED: begin
            // After granting access, lock the system
            next_state = ST_LOCKED;
        end

        ST_LOCKED: begin
            // Remain locked until reset
            next_state = ST_LOCKED;
        end

        ST_ERROR: begin
            // INTENTIONAL FLAW:
            // No outgoing transitions from ST_ERROR
            // The FSM is permanently stuck here
            next_state = ST_ERROR;
        end
    endcase
end

// Output logic
always @(*) begin
    access_granted = 1'b0;
    if (state == ST_GRANTED)
        access_granted = 1'b1;
end
endmodule