// Authentication / Authorization Controller with Intentional FSM Weakness
// Domain: Authentication/authorization system
// NOTE: This module intentionally contains an improper FSM (CWE-1245)

module auth_controller (
    input  wire        clk,
    input  wire        rst_n,

    // External interface
    input  wire        login_req,
    input  wire        logout_req,
    input  wire        cred_valid,
    input  wire        admin_mode_req,
    input  wire [7:0]  user_id,

    output reg         auth_granted,
    output reg         admin_granted,
    output reg         session_active,
    output reg  [3:0]  error_code
);

    // ------------------------------------------------------------
    // Authentication FSM (security-critical)
    // ------------------------------------------------------------
    // 3-bit state register allows 8 encodings, but not all are covered
    reg [2:0] auth_state;

    localparam AUTH_IDLE        = 3'd0;
    localparam AUTH_COLLECT     = 3'd1;
    localparam AUTH_VERIFY      = 3'd2;
    localparam AUTH_SUCCESS     = 3'd3;
    localparam AUTH_FAIL        = 3'd4;
    localparam AUTH_LOCKED      = 3'd5; // Deadlock state (intentional)
    localparam AUTH_DEBUG       = 3'd6; // Unreachable state (intentional)

    // Simple attempt counter
    reg [2:0] attempt_cnt;

    // ------------------------------------------------------------
    // Session FSM (interacting FSM)
    // ------------------------------------------------------------
    reg [1:0] session_state;

    localparam SES_IDLE     = 2'd0;
    localparam SES_ACTIVE   = 2'd1;
    localparam SES_ADMIN    = 2'd2;
    localparam SES_EXPIRED  = 2'd3;

    // Session timer
    reg [7:0] session_timer;

    // ------------------------------------------------------------
    // Authentication FSM Logic
    // ------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            auth_state    <= AUTH_IDLE;
            attempt_cnt  <= 3'd0;
            auth_granted <= 1'b0;
            admin_granted<= 1'b0;
            error_code   <= 4'd0;
        end else begin
            case (auth_state)

                AUTH_IDLE: begin
                    auth_granted  <= 1'b0;
                    admin_granted <= 1'b0;
                    if (login_req)
                        auth_state <= AUTH_COLLECT;
                end

                AUTH_COLLECT: begin
                    if (cred_valid)
                        auth_state <= AUTH_VERIFY;
                end

                AUTH_VERIFY: begin
                    if (cred_valid && user_id != 8'h00) begin
                        auth_state   <= AUTH_SUCCESS;
                        attempt_cnt <= 3'd0;
                    end else begin
                        auth_state   <= AUTH_FAIL;
                        attempt_cnt <= attempt_cnt + 3'd1;
                    end
                end

                AUTH_SUCCESS: begin
                    auth_granted <= 1'b1;
                    if (admin_mode_req)
                        admin_granted <= 1'b1;
                    auth_state <= AUTH_IDLE;
                end

                AUTH_FAIL: begin
                    error_code <= 4'hF;
                    if (attempt_cnt >= 3'd3)
                        auth_state <= AUTH_LOCKED; // enters deadlock
                    else
                        auth_state <= AUTH_IDLE;
                end

                AUTH_LOCKED: begin
                    // INTENTIONAL DEADLOCK:
                    // No transition out of AUTH_LOCKED under any condition
                    error_code <= 4'hA;
                end

                // AUTH_DEBUG is intentionally unreachable:
                // No transition in the FSM ever assigns this state.

            endcase
        end
    end

    // ------------------------------------------------------------
    // Session FSM Logic (dependent on authentication FSM)
    // ------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            session_state  <= SES_IDLE;
            session_timer <= 8'd0;
            session_active<= 1'b0;
        end else begin
            case (session_state)

                SES_IDLE: begin
                    session_active <= 1'b0;
                    if (auth_granted) begin
                        session_state  <= SES_ACTIVE;
                        session_timer <= 8'd100;
                    end
                end

                SES_ACTIVE: begin
                    session_active <= 1'b1;
                    session_timer <= session_timer - 8'd1;
                    if (admin_granted)
                        session_state <= SES_ADMIN;
                    else if (session_timer == 8'd0)
                        session_state <= SES_EXPIRED;
                end

                SES_ADMIN: begin
                    session_active <= 1'b1;
                    if (logout_req)
                        session_state <= SES_IDLE;
                end

                SES_EXPIRED: begin
                    session_active <= 1'b0;
                    if (login_req)
                        session_state <= SES_IDLE;
                end

                // INTENTIONAL INCOMPLETE STATE COVERAGE:
                // No default case provided.
                // If session_state enters an illegal encoding, it will persist.

            endcase
        end
    end

endmodule
