module insecure_access_fsm (
    input  wire        clk,
    input  wire        reset_n,
    input  wire        start_auth,
    input  wire        auth_ok,
    input  wire        lock,
    output reg         access_granted
);

    // 3-bit state register (allows 8 possible states)
    reg [2:0] state;
    reg [2:0] next_state;

    // State encoding
    localparam IDLE      = 3'd0;
    localparam AUTH      = 3'd1;
    localparam GRANTED   = 3'd2;
    localparam LOCKED    = 3'd3;
    localparam DEADLOCK  = 3'd4;
    localparam UNUSED    = 3'd5; // Unreachable state

    // State register
    always @(posedge clk or negedge reset_n) begin
        if (!reset_n)
            state <= IDLE;
        else
            state <= next_state;
    end

    // Next-state logic (INTENTIONALLY IMPROPER FSM)
    always @(*) begin
        // Default behavior: remain in current state
        next_state = state;

        case (state)
            IDLE: begin
                if (start_auth)
                    next_state = AUTH;
            end
            AUTH: begin
                if (auth_ok)
                    next_state = GRANTED;
                else
                    next_state = DEADLOCK; // Failed auth leads to deadlock
            end
            GRANTED: begin
                if (lock)
                    next_state = LOCKED;
            end
            LOCKED: begin
                // No transition defined back to IDLE or AUTH
                // System is effectively stuck unless reset
                next_state = LOCKED;
            end
            DEADLOCK: begin
                // Deadlock state: no exit transitions
                next_state = DEADLOCK;
            end
            // UNUSED state is intentionally not transitioned to
            // No default case provided (incomplete state coverage)
        endcase
    end
    // Output logic
    always @(*) begin
        case (state)
            GRANTED:
                access_granted = 1'b1;
            default:
                access_granted = 1'b0;
        endcase
    end

endmodule