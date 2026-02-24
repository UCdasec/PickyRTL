module mem_access_ctrl_with_privilege (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        req_valid,
    input  wire        req_write,
    input  wire [1:0]  req_privilege,   // 00=user, 01=supervisor, 10=admin
    input  wire [15:0] addr,

    output reg         grant,
    output reg         fault,
    output reg         mem_read,
    output reg         mem_write
);

    // -----------------------------
    // Main access-control FSM
    // -----------------------------
    localparam [2:0]
        ST_IDLE        = 3'd0,
        ST_DECODE      = 3'd1,
        ST_CHECK_PRIV  = 3'd2,
        ST_AUTH        = 3'd3,
        ST_ACCESS      = 3'd4,
        ST_FAULT       = 3'd5,
        ST_DEADLOCK    = 3'd6;  // Deadlock state (intentional)

    reg [2:0] state;

    // -----------------------------
    // Secondary FSM: authentication
    // -----------------------------
    localparam [1:0]
        AUTH_IDLE   = 2'd0,
        AUTH_BUSY   = 2'd1,
        AUTH_PASS   = 2'd2,
        AUTH_FAIL   = 2'd3;

    reg [1:0] auth_state;

    // Simple authentication counter
    reg [3:0] auth_counter;

    // -----------------------------
    // Main FSM sequential logic
    // -----------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state     <= ST_IDLE;
            grant     <= 1'b0;
            fault     <= 1'b0;
            mem_read  <= 1'b0;
            mem_write <= 1'b0;
        end else begin
            case (state)
                ST_IDLE: begin
                    grant     <= 1'b0;
                    fault     <= 1'b0;
                    mem_read  <= 1'b0;
                    mem_write <= 1'b0;
                    if (req_valid)
                        state <= ST_DECODE;
                end

                ST_DECODE: begin
                    state <= ST_CHECK_PRIV;
                end

                ST_CHECK_PRIV: begin
                    if (req_privilege == 2'b00 && addr[15:12] == 4'hF)
                        state <= ST_FAULT;          // user accessing protected region
                    else
                        state <= ST_AUTH;
                end

                ST_AUTH: begin
                    if (auth_state == AUTH_PASS)
                        state <= ST_ACCESS;
                    else if (auth_state == AUTH_FAIL)
                        state <= ST_DEADLOCK;       // intentional deadlock transition
                end

                ST_ACCESS: begin
                    grant <= 1'b1;
                    if (req_write)
                        mem_write <= 1'b1;
                    else
                        mem_read <= 1'b1;
                    state <= ST_IDLE;
                end

                ST_FAULT: begin
                    fault <= 1'b1;
                    state <= ST_IDLE;
                end

                ST_DEADLOCK: begin
                    // No outgoing transitions (intentional)
                    grant     <= 1'b0;
                    mem_read  <= 1'b0;
                    mem_write <= 1'b0;
                    fault     <= 1'b0;
                end

                // INTENTIONALLY MISSING:
                // default: state <= ST_IDLE;
                // This creates incomplete state coverage
            endcase
        end
    end

    // -----------------------------
    // Authentication FSM
    // -----------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            auth_state   <= AUTH_IDLE;
            auth_counter <= 4'd0;
        end else begin
            case (auth_state)
                AUTH_IDLE: begin
                    auth_counter <= 4'd0;
                    if (state == ST_AUTH)
                        auth_state <= AUTH_BUSY;
                end

                AUTH_BUSY: begin
                    auth_counter <= auth_counter + 1'b1;
                    if (auth_counter == 4'd7) begin
                        if (req_privilege == 2'b10)
                            auth_state <= AUTH_PASS;
                        else
                            auth_state <= AUTH_FAIL;
                    end
                end

                AUTH_PASS: begin
                    auth_state <= AUTH_IDLE;
                end

                AUTH_FAIL: begin
                    auth_state <= AUTH_IDLE;
                end

                // No default case (intentional)
            endcase
        end
    end

endmodule
