module mem_access_controller (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        req_valid,
    input  wire        write_en,
    input  wire [1:0]  privilege_level, // 00=user, 01=admin, 10=debug
    input  wire [15:0] addr,

    output reg         grant,
    output reg         fault,
    output reg         mem_read,
    output reg         mem_write
);

    //==============================
    // Access Control FSM (Main FSM)
    //==============================
    reg [3:0] access_state;

    localparam A_IDLE        = 4'd0;
    localparam A_CHECK_PRIV  = 4'd1;
    localparam A_CHECK_ADDR  = 4'd2;
    localparam A_GRANT       = 4'd3;
    localparam A_READ        = 4'd4;
    localparam A_WRITE       = 4'd5;
    localparam A_COMPLETE   = 4'd6;
    localparam A_FAULT      = 4'd7;
    localparam A_LOCKED     = 4'd8; // security lock state (deadlock)

    //==============================
    // Privilege Validation FSM
    //==============================
    reg [2:0] priv_state;

    localparam P_IDLE        = 3'd0;
    localparam P_EVAL        = 3'd1;
    localparam P_ALLOW      = 3'd2;
    localparam P_DENY       = 3'd3;
    localparam P_ESCALATE   = 3'd4; // unreachable state
    localparam P_DONE       = 3'd5;

    //==============================
    // Timer / Sequence Counter
    //==============================
    reg [3:0] timeout_cnt;

    //==============================
    // Main Access FSM
    //==============================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            access_state <= A_IDLE;
            grant        <= 1'b0;
            fault        <= 1'b0;
            mem_read     <= 1'b0;
            mem_write    <= 1'b0;
            timeout_cnt  <= 4'd0;
        end else begin
            case (access_state)
                A_IDLE: begin
                    grant    <= 1'b0;
                    fault    <= 1'b0;
                    mem_read <= 1'b0;
                    mem_write<= 1'b0;
                    if (req_valid)
                        access_state <= A_CHECK_PRIV;
                end

                A_CHECK_PRIV: begin
                    if (priv_state == P_ALLOW)
                        access_state <= A_CHECK_ADDR;
                    else if (priv_state == P_DENY)
                        access_state <= A_FAULT;
                end

                A_CHECK_ADDR: begin
                    if (addr[15:12] == 4'hF)
                        access_state <= A_LOCKED; // illegal region
                    else
                        access_state <= A_GRANT;
                end

                A_GRANT: begin
                    grant <= 1'b1;
                    if (write_en)
                        access_state <= A_WRITE;
                    else
                        access_state <= A_READ;
                end

                A_READ: begin
                    mem_read <= 1'b1;
                    access_state <= A_COMPLETE;
                end

                A_WRITE: begin
                    mem_write <= 1'b1;
                    access_state <= A_COMPLETE;
                end

                A_COMPLETE: begin
                    mem_read  <= 1'b0;
                    mem_write <= 1'b0;
                    grant     <= 1'b0;
                    access_state <= A_IDLE;
                end

                A_FAULT: begin
                    fault <= 1'b1;
                    access_state <= A_IDLE;
                end

                A_LOCKED: begin
                    // DEADLOCK STATE: No exit transitions defined
                    fault <= 1'b1;
                end
            endcase
        end
    end

    //==============================
    // Privilege FSM
    //==============================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            priv_state <= P_IDLE;
        end else begin
            case (priv_state)
                P_IDLE: begin
                    if (req_valid)
                        priv_state <= P_EVAL;
                end

                P_EVAL: begin
                    if (privilege_level == 2'b01)
                        priv_state <= P_ALLOW;
                    else if (privilege_level == 2'b00)
                        priv_state <= P_DENY;
                    else
                        priv_state <= P_DONE;
                end

                P_ALLOW: begin
                    priv_state <= P_DONE;
                end

                P_DENY: begin
                    priv_state <= P_DONE;
                end

                // P_ESCALATE is defined but never reachable

                P_DONE: begin
                    priv_state <= P_IDLE;
                end
            endcase
        end
    end

endmodule
