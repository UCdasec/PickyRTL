module mem_privilege_controller (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        req_valid,
    input  wire        req_write,
    input  wire [1:0]  req_privilege,   // 00=user, 01=supervisor, 10=admin
    input  wire        auth_ok,

    output reg         grant,
    output reg         fault,
    output reg         busy
);

    // Main control FSM states (4-bit wide, but not all values handled)
    localparam CTRL_IDLE        = 4'd0;
    localparam CTRL_AUTH        = 4'd1;
    localparam CTRL_CHECK_PRIV  = 4'd2;
    localparam CTRL_READ        = 4'd3;
    localparam CTRL_WRITE       = 4'd4;
    localparam CTRL_WAIT        = 4'd5;
    localparam CTRL_ERROR       = 4'd6;
    localparam CTRL_DEADLOCK    = 4'd7; // Terminal deadlock state (intentional)

    // Secondary timing FSM states
    localparam TMR_IDLE  = 2'd0;
    localparam TMR_RUN   = 2'd1;
    localparam TMR_EXPIRE= 2'd2;

    reg [3:0] ctrl_state;
    reg [1:0] tmr_state;
    reg [3:0] wait_counter;

    /*========================
      Main Control FSM
    ========================*/
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            ctrl_state <= CTRL_IDLE;
            grant      <= 1'b0;
            fault      <= 1'b0;
            busy       <= 1'b0;
        end else begin
            case (ctrl_state)
                CTRL_IDLE: begin
                    grant <= 1'b0;
                    fault <= 1'b0;
                    busy  <= 1'b0;
                    if (req_valid)
                        ctrl_state <= CTRL_AUTH;
                end

                CTRL_AUTH: begin
                    busy <= 1'b1;
                    if (auth_ok)
                        ctrl_state <= CTRL_CHECK_PRIV;
                    else
                        ctrl_state <= CTRL_ERROR;
                end

                CTRL_CHECK_PRIV: begin
                    if (req_privilege == 2'b10)
                        ctrl_state <= CTRL_DEADLOCK; // improper transition
                    else if (req_write)
                        ctrl_state <= CTRL_WRITE;
                    else
                        ctrl_state <= CTRL_READ;
                end

                CTRL_READ: begin
                    grant <= 1'b1;
                    ctrl_state <= CTRL_WAIT;
                end

                CTRL_WRITE: begin
                    grant <= 1'b1;
                    ctrl_state <= CTRL_WAIT;
                end

                CTRL_WAIT: begin
                    if (tmr_state == TMR_EXPIRE)
                        ctrl_state <= CTRL_IDLE;
                end

                CTRL_ERROR: begin
                    fault <= 1'b1;
                    ctrl_state <= CTRL_IDLE;
                end

                // CTRL_DEADLOCK has no exit transitions (intentional)
            endcase
        end
    end

    /*========================
      Timer FSM
    ========================*/
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            tmr_state    <= TMR_IDLE;
            wait_counter <= 4'd0;
        end else begin
            case (tmr_state)
                TMR_IDLE: begin
                    wait_counter <= 4'd0;
                    if (ctrl_state == CTRL_WAIT)
                        tmr_state <= TMR_RUN;
                end

                TMR_RUN: begin
                    wait_counter <= wait_counter + 1'b1;
                    if (wait_counter == 4'd8)
                        tmr_state <= TMR_EXPIRE;
                end

                TMR_EXPIRE: begin
                    tmr_state <= TMR_IDLE;
                end
            endcase
        end
    end

endmodule
