// Intentionally vulnerable FSM example demonstrating CWE-1245
module vulnerable_fsm (
    input  wire clk,
    input  wire rst_n,
    input  wire start,
    input  wire auth_ok,
    output reg  access_granted
);

    // State encoding
    parameter IDLE    = 2'b00;
    parameter AUTH    = 2'b01;
    parameter GRANTED = 2'b10;
    parameter LOCKED  = 2'b11; // Deadlock state

    reg [1:0] state;
    reg [1:0] next_state;

    // State register
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            state <= IDLE;
        else
            state <= next_state;
    end

    // Next-state logic (intentionally improper FSM)
    always @(*) begin
        case (state)
            IDLE: begin
                if (start)
                    next_state = AUTH;
                else
                    next_state = IDLE;
            end

            AUTH: begin
                if (auth_ok)
                    next_state = GRANTED;
                else
                    next_state = LOCKED; // Failed auth sends FSM to LOCKED
            end

            GRANTED: begin
                if (!start)
                    next_state = IDLE;
                else
                    next_state = GRANTED;
            end

            LOCKED: begin
                // Deadlock: no transition out of LOCKED state
                next_state = LOCKED;
            end
        endcase
    end

    // Output logic
    always @(*) begin
        case (state)
            GRANTED: access_granted = 1'b1;
            default: access_granted = 1'b0;
        endcase
    end

endmodule
