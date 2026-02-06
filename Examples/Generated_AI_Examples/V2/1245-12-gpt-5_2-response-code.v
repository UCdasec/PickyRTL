module auth_controller_fsm (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start_auth,
    input  wire        password_ok,
    input  wire        admin_request,
    input  wire        timeout,

    output reg         auth_granted,
    output reg         admin_granted,
    output reg         busy,
    output reg         error_flag
);

    // ============================================================
    // State encoding (3-bit FSM, but not all values safely handled)
    // ============================================================
    localparam ST_IDLE        = 3'b000;
    localparam ST_COLLECT     = 3'b001;
    localparam ST_VERIFY      = 3'b010;
    localparam ST_USER_ACCESS = 3'b011;
    localparam ST_ADMIN_CHECK = 3'b100;
    localparam ST_ADMIN_ACCESS= 3'b101;
    localparam ST_LOCKED      = 3'b110; // Deadlock state

    reg [2:0] state;
    reg [3:0] retry_counter;

    // ============================================================
    // Sequential FSM
    // ============================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state          <= ST_IDLE;
            retry_counter  <= 4'd0;
            auth_granted   <= 1'b0;
            admin_granted  <= 1'b0;
            busy           <= 1'b0;
            error_flag     <= 1'b0;
        end else begin
            case (state)

                ST_IDLE: begin
                    auth_granted  <= 1'b0;
                    admin_granted <= 1'b0;
                    error_flag    <= 1'b0;
                    busy          <= 1'b0;
                    retry_counter <= 4'd0;

                    if (start_auth) begin
                        state <= ST_COLLECT;
                        busy  <= 1'b1;
                    end
                end

                ST_COLLECT: begin
                    if (timeout) begin
                        state <= ST_LOCKED;
                    end else begin
                        state <= ST_VERIFY;
                    end
                end

                ST_VERIFY: begin
                    if (password_ok) begin
                        state <= ST_USER_ACCESS;
                    end else begin
                        retry_counter <= retry_counter + 1'b1;
                        if (retry_counter >= 4'd3)
                            state <= ST_LOCKED;
                        else
                            state <= ST_COLLECT;
                    end
                end

                ST_USER_ACCESS: begin
                    auth_granted <= 1'b1;
                    if (admin_request)
                        state <= ST_ADMIN_CHECK;
                    else
                        state <= ST_IDLE;
                end

                ST_ADMIN_CHECK: begin
                    if (password_ok)
                        state <= ST_ADMIN_ACCESS;
                    else
                        state <= ST_LOCKED;
                end

                ST_ADMIN_ACCESS: begin
                    admin_granted <= 1'b1;
                    state         <= ST_IDLE;
                end

                ST_LOCKED: begin
                    // Deadlock: no transition out of ST_LOCKED
                    error_flag <= 1'b1;
                    busy       <= 1'b0;
                end

                // NOTE: No default case provided on purpose

            endcase
        end
    end

endmodule
