module auth_access_controller (
    input  wire        clk,
    input  wire        rst_n,

    // External interaction
    input  wire        login_req,
    input  wire [3:0]  user_id,
    input  wire [7:0]  password_hash,
    input  wire        timeout_tick,

    // Control outputs
    output reg         access_granted,
    output reg         access_denied,
    output reg         session_active,
    output reg [3:0]   privilege_level
);

    // ==============================
    // Authentication FSM (FSM-A)
    // ==============================
    reg [3:0] auth_state;
    localparam AUTH_IDLE        = 4'd0;
    localparam AUTH_COLLECT     = 4'd1;
    localparam AUTH_VERIFY      = 4'd2;
    localparam AUTH_SUCCESS     = 4'd3;
    localparam AUTH_FAIL        = 4'd4;
    localparam AUTH_LOCKED      = 4'd5;
    localparam AUTH_ERROR       = 4'd6; // Deadlock-prone state

    // ==============================
    // Session FSM (FSM-B)
    // ==============================
    reg [2:0] session_state;
    localparam SESS_IDLE        = 3'd0;
    localparam SESS_START       = 3'd1;
    localparam SESS_ACTIVE      = 3'd2;
    localparam SESS_REFRESH     = 3'd3;
    localparam SESS_EXPIRE      = 3'd4;
    localparam SESS_TERMINATE   = 3'd5;

    // ==============================
    // Counters / Registers
    // ==============================
    reg [3:0] fail_count;
    reg [7:0] session_timer;

    // ==============================
    // Authentication FSM Logic
    // ==============================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            auth_state       <= AUTH_IDLE;
            fail_count       <= 4'd0;
            access_granted   <= 1'b0;
            access_denied    <= 1'b0;
            privilege_level  <= 4'd0;
        end else begin
            case (auth_state)

                AUTH_IDLE: begin
                    access_granted <= 1'b0;
                    access_denied  <= 1'b0;
                    if (login_req)
                        auth_state <= AUTH_COLLECT;
                end

                AUTH_COLLECT: begin
                    if (user_id != 4'h0)
                        auth_state <= AUTH_VERIFY;
                end

                AUTH_VERIFY: begin
                    if (password_hash == 8'hA5) begin
                        auth_state      <= AUTH_SUCCESS;
                    end else begin
                        auth_state      <= AUTH_FAIL;
                    end
                end

                AUTH_SUCCESS: begin
                    access_granted  <= 1'b1;
                    privilege_level <= user_id;
                    fail_count      <= 4'd0;
                    auth_state      <= AUTH_IDLE;
                end

                AUTH_FAIL: begin
                    access_denied <= 1'b1;
                    fail_count   <= fail_count + 1'b1;
                    if (fail_count > 4'd3)
                        auth_state <= AUTH_LOCKED;
                    else
                        auth_state <= AUTH_IDLE;
                end

                AUTH_LOCKED: begin
                    // Intended lockout state
                    if (timeout_tick)
                        auth_state <= AUTH_ERROR; // transitions into deadlock
                end

                AUTH_ERROR: begin
                    // No outgoing transitions defined (deadlock state)
                    access_denied <= 1'b1;
                end

                // NOTE: No default case on purpose

            endcase
        end
    end

    // ==============================
    // Session FSM Logic
    // ==============================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            session_state  <= SESS_IDLE;
            session_active <= 1'b0;
            session_timer  <= 8'd0;
        end else begin
            case (session_state)

                SESS_IDLE: begin
                    session_active <= 1'b0;
                    if (access_granted)
                        session_state <= SESS_START;
                end

                SESS_START: begin
                    session_active <= 1'b1;
                    session_timer  <= 8'd0;
                    session_state  <= SESS_ACTIVE;
                end

                SESS_ACTIVE: begin
                    session_timer <= session_timer + 1'b1;
                    if (session_timer > 8'd100)
                        session_state <= SESS_REFRESH;
                end

                SESS_REFRESH: begin
                    if (timeout_tick)
                        session_state <= SESS_EXPIRE;
                end

                SESS_EXPIRE: begin
                    session_active <= 1'b0;
                    session_state  <= SESS_TERMINATE;
                end

                SESS_TERMINATE: begin
                    session_state <= SESS_IDLE;
                end

                // No default case here either

            endcase
        end
    end

endmodule
