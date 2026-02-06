module insecure_fsm_example (
input  wire clk,
input  wire rst_n,
input  wire start,
input  wire auth_ok,
output reg  busy,
output reg  error
);

// State encoding
reg [2:0] state, next_state;

localparam S_IDLE   = 3'b000;
localparam S_AUTH   = 3'b001;
localparam S_RUN    = 3'b010;
localparam S_LOCK   = 3'b011; // Deadlock state
localparam S_UNUSED = 3'b100; // Unreachable state

// State register
always @(posedge clk or negedge rst_n) begin
    if (!rst_n)
        state <= S_IDLE;
    else
        state <= next_state;
end

// Next-state logic (intentionally improper FSM)
always @(*) begin
    next_state = state; // default: remain in current state

    case (state)
        S_IDLE: begin
            if (start)
                next_state = S_AUTH;
        end

        S_AUTH: begin
            if (auth_ok)
                next_state = S_RUN;
            else
                next_state = S_LOCK; // enter deadlock state on failure
        end

        S_RUN: begin
            // Normal operation, no exit condition defined
            next_state = S_RUN;
        end

        S_LOCK: begin
            // Deadlock: no transition out of this state
            next_state = S_LOCK;
        end

        // Note: S_UNUSED is never transitioned to

        default: begin
            next_state = state;
        end
    endcase
end

// Output logic
always @(*) begin
    busy  = 1'b0;
    error = 1'b0;

    case (state)
        S_IDLE: begin
            busy = 1'b0;
        end

        S_AUTH: begin
            busy = 1'b1;
        end

        S_RUN: begin
            busy = 1'b1;
        end

        S_LOCK: begin
            busy  = 1'b0;
            error = 1'b1;
        end

        default: begin
            busy  = 1'b0;
            error = 1'b0;
        end
    endcase
end
endmodule