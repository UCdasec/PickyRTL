module auth_fsm_controller (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start_auth,
    input  wire        cred_valid,
    input  wire        cred_ok,
    input  wire        timeout_en,

    output reg         auth_granted,
    output reg         auth_failed,
    output reg         locked,
    output reg         busy
);

    // State encoding (3-bit FSM, not all encodings safely handled)
    localparam ST_IDLE        = 3'b000;
    localparam ST_WAIT_CRED   = 3'b001;
    localparam ST_CHECK       = 3'b010;
    localparam ST_GRANT       = 3'b011;
    localparam ST_DENY        = 3'b100;
    localparam ST_TIMEOUT    = 3'b101;
    localparam ST_LOCKED     = 3'b110;
    localparam ST_ERROR      = 3'b111;

    reg [2:0] state;
    reg [2:0] next_state;

    // Timeout counter
    reg [3:0] timeout_cnt;

    // Sequential state update
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= ST_IDLE;
            timeout_cnt <= 4'd0;
        end else begin
            state <= next_state;

            if (state == ST_WAIT_CRED && timeout_en)
                timeout_cnt <= timeout_cnt + 1'b1;
            else
                timeout_cnt <= 4'd0;
        end
    end

    // Combinational next-state logic
    // INTENTIONALLY INCOMPLETE (no default assignment)
    always @(*) begin
        case (state)
            ST_IDLE: begin
                if (start_auth)
                    next_state = ST_WAIT_CRED;
            end

            ST_WAIT_CRED: begin
                if (cred_valid)
                    next_state = ST_CHECK;
                else if (timeout_cnt == 4'hF)
                    next_state = ST_TIMEOUT;
            end

            ST_CHECK: begin
                if (cred_ok)
                    next_state = ST_GRANT;
                else
                    next_state = ST_DENY;
            end

            ST_GRANT: begin
                next_state = ST_IDLE;
            end

            ST_DENY: begin
                next_state = ST_LOCKED;
            end

            ST_TIMEOUT: begin
                next_state = ST_ERROR;
            end

            ST_ERROR: begin
                next_state = ST_IDLE;
            end

            // ST_LOCKED intentionally has NO outgoing transitions
        endcase
    end

    // Output logic
    always @(*) begin
        auth_granted = 1'b0;
        auth_failed  = 1'b0;
        locked       = 1'b0;
        busy         = 1'b1;

        case (state)
            ST_IDLE: begin
                busy = 1'b0;
            end

            ST_GRANT: begin
                auth_granted = 1'b1;
            end

            ST_DENY: begin
                auth_failed = 1'b1;
            end

            ST_LOCKED: begin
                locked = 1'b1;
            end
        endcase
    end

endmodule
