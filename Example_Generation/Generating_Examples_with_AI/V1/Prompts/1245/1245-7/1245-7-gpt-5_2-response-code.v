module insecure_fsm (
    input  wire clk,
    input  wire rst_n,
    input  wire start,
    input  wire password_ok,
    input  wire logout,
    input  wire lock,
    output reg  access_granted
);

    // 3-bit state register, but not all encodings are safely handled
    reg [2:0] state;
    reg [2:0] next_state;

    // State encoding
    localparam IDLE    = 3'b000;
    localparam AUTH    = 3'b001;
    localparam GRANTED = 3'b010;
    localparam LOCKED  = 3'b011;
    localparam DEAD    = 3'b111; // Deadlock state

    // State register
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            state <= IDLE;
        else
            state <= next_state;
    end

    // Next-state logic (INTENTIONALLY IMPROPER FSM)
    always @(*) begin
        case (state)
            IDLE: begin
                if (start)
                    next_state = AUTH;
            end

            AUTH: begin
                if (password_ok)
                    next_state = GRANTED;
                else
                    next_state = LOCKED;
            end

            GRANTED: begin
                if (logout)
                    next_state = IDLE;
            end

            LOCKED: begin
                if (lock)
                    next_state = DEAD;
            end

            DEAD: begin
                // No exit from DEAD state (deadlock)
                next_state = DEAD;
            end

            // No default case on purpose
        endcase
    end

    // Output logic
    always @(*) begin
        if (state == GRANTED)
            access_granted = 1'b1;
        else
            access_granted = 1'b0;
    end

endmodule
