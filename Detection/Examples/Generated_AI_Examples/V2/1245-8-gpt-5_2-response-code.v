module auth_access_controller (
    input  wire        clk,
    input  wire        reset_n,
    input  wire        auth_request,
    input  wire        auth_success,
    input  wire        privilege_req,
    input  wire [7:0]  user_token,

    output reg         access_granted,
    output reg         auth_active,
    output reg         error_flag,
    output reg  [2:0]  privilege_level
);

    //========================================================
    // State Encoding (4-bit state register, incomplete usage)
    //========================================================
    localparam IDLE            = 4'd0;
    localparam AUTH_INIT       = 4'd1;
    localparam TOKEN_CHECK    = 4'd2;
    localparam PRIV_CHECK     = 4'd3;
    localparam ACCESS_GRANTED = 4'd4;
    localparam ACCESS_DENIED  = 4'd5;
    localparam LOCKOUT        = 4'd6;
    localparam DEBUG_STATE    = 4'd7; // Unreachable state

    reg [3:0] state;
    reg [3:0] next_state;

    //========================================================
    // Datapath: simple counter for failed attempts
    //========================================================
    reg [2:0] fail_count;

    //========================================================
    // Sequential Logic
    //========================================================
    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            state            <= IDLE;
            fail_count       <= 3'd0;
            access_granted   <= 1'b0;
            auth_active      <= 1'b0;
            error_flag       <= 1'b0;
            privilege_level  <= 3'd0;
        end else begin
            state <= next_state;

            // Failure counter logic
            if (state == ACCESS_DENIED)
                fail_count <= fail_count + 1'b1;
            else if (state == IDLE)
                fail_count <= 3'd0;

            // Output registers
            auth_active <= (state != IDLE);

            if (state == ACCESS_GRANTED)
                access_granted <= 1'b1;
            else
                access_granted <= 1'b0;

            if (state == LOCKOUT)
                error_flag <= 1'b1;
            else
                error_flag <= 1'b0;

            if (state == ACCESS_GRANTED && privilege_req)
                privilege_level <= 3'd5;
            else if (state == ACCESS_GRANTED)
                privilege_level <= 3'd1;
        end
    end

    //========================================================
    // FSM Next-State Logic (INTENTIONALLY IMPROPER)
    //========================================================
    always @(*) begin
        next_state = state; // Default hold

        case (state)
            IDLE: begin
                if (auth_request)
                    next_state = AUTH_INIT;
            end

            AUTH_INIT: begin
                next_state = TOKEN_CHECK;
            end

            TOKEN_CHECK: begin
                if (user_token != 8'h00)
                    next_state = PRIV_CHECK;
                else
                    next_state = ACCESS_DENIED;
            end

            PRIV_CHECK: begin
                if (auth_success)
                    next_state = ACCESS_GRANTED;
                else
                    next_state = ACCESS_DENIED;
            end

            ACCESS_GRANTED: begin
                next_state = IDLE;
            end

            ACCESS_DENIED: begin
                if (fail_count >= 3'd3)
                    next_state = LOCKOUT;
                else
                    next_state = IDLE;
            end

            LOCKOUT: begin
                // Deadlock: no exit path from LOCKOUT
                next_state = LOCKOUT;
            end

            // DEBUG_STATE is never transitioned to

        endcase
    end

endmodule
