module access_fsm (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        request,
    input  wire        auth_ok,
    input  wire        force_error,
    output reg         grant
);

    // 3-bit state register, but not all values are safely handled
    reg [2:0] state;
    reg [2:0] next_state;

    // State encoding
    localparam IDLE   = 3'b000;
    localparam AUTH   = 3'b001;
    localparam GRANT  = 3'b010;
    localparam LOCKED = 3'b011;
    localparam ERROR  = 3'b100;

    // State register
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            state <= IDLE;
        else
            state <= next_state;
    end

    // Next-state logic (INTENTIONALLY IMPROPER)
    always @(*) begin
        case (state)
            IDLE: begin
                if (request)
                    next_state = AUTH;
                else
                    next_state = IDLE;
            end

            AUTH: begin
                if (auth_ok)
                    next_state = GRANT;
                else
                    next_state = LOCKED;
            end

            GRANT: begin
                if (force_error)
                    next_state = ERROR;
                else
                    next_state = IDLE;
            end

            LOCKED: begin
                // LOCKED state has only one exit condition
                if (request && auth_ok)
                    next_state = AUTH;
                else
                    next_state = LOCKED;
            end

            ERROR: begin
                // DEADLOCK: once entered, no transition out
                next_state = ERROR;
            end

            // No default case on purpose
        endcase
    end

    // Output logic
    always @(*) begin
        case (state)
            GRANT:  grant = 1'b1;
            default: grant = 1'b0;
        endcase
    end

endmodule
