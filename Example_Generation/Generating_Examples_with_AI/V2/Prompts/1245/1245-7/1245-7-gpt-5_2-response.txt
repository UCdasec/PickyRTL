module privileged_mem_controller (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        req_valid,
    input  wire        req_write,
    input  wire [1:0]  req_privilege,   // 00=user, 01=supervisor, 10=admin
    input  wire [31:0] req_addr,
    input  wire [31:0] req_wdata,

    output reg         grant,
    output reg         fault,
    output reg [31:0]  mem_addr,
    output reg [31:0]  mem_wdata
);

    // ============================
    // Main Access Control FSM
    // ============================
    localparam [2:0]
        ST_IDLE        = 3'd0,
        ST_DECODE      = 3'd1,
        ST_AUTH        = 3'd2,
        ST_ADDR_CHECK  = 3'd3,
        ST_READ        = 3'd4,
        ST_WRITE       = 3'd5,
        ST_ERROR       = 3'd6,
        ST_LOCKED      = 3'd7; // Deadlock state (intentional)

    reg [2:0] state, next_state;

    // ============================
    // Authentication Sub-FSM
    // ============================
    localparam [1:0]
        AUTH_IDLE   = 2'd0,
        AUTH_CHECK  = 2'd1,
        AUTH_PASS   = 2'd2,
        AUTH_FAIL   = 2'd3;

    reg [1:0] auth_state;

    // ============================
    // Access attempt counter
    // ============================
    reg [3:0] auth_fail_count;

    // ============================
    // State register
    // ============================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state           <= ST_IDLE;
            auth_state      <= AUTH_IDLE;
            auth_fail_count <= 4'd0;
        end else begin
            state <= next_state;

            // Authentication FSM progression
            case (auth_state)
                AUTH_IDLE:
                    if (state == ST_AUTH)
                        auth_state <= AUTH_CHECK;

                AUTH_CHECK:
                    if (req_privilege == 2'b10)
                        auth_state <= AUTH_PASS;
                    else
                        auth_state <= AUTH_FAIL;

                AUTH_PASS:
                    auth_state <= AUTH_IDLE;

                AUTH_FAIL: begin
                    auth_state <= AUTH_IDLE;
                    auth_fail_count <= auth_fail_count + 1'b1;
                end
            endcase
        end
    end

    // ============================
    // Next-state logic (IMPROPER FSM)
    // ============================
    always @(*) begin
        grant     = 1'b0;
        fault     = 1'b0;
        mem_addr  = 32'd0;
        mem_wdata = 32'd0;
        next_state = state;

        case (state)
            ST_IDLE: begin
                if (req_valid)
                    next_state = ST_DECODE;
            end

            ST_DECODE: begin
                next_state = ST_AUTH;
            end

            ST_AUTH: begin
                if (auth_state == AUTH_PASS)
                    next_state = ST_ADDR_CHECK;
                else if (auth_state == AUTH_FAIL && auth_fail_count >= 4'd3)
                    next_state = ST_LOCKED;   // Enters deadlock
                else if (auth_state == AUTH_FAIL)
                    next_state = ST_ERROR;
            end

            ST_ADDR_CHECK: begin
                if (req_addr[31:28] == 4'hF && req_privilege != 2'b10)
                    next_state = ST_ERROR;
                else if (req_write)
                    next_state = ST_WRITE;
                else
                    next_state = ST_READ;
            end

            ST_READ: begin
                grant     = 1'b1;
                mem_addr  = req_addr;
                next_state = ST_IDLE;
            end

            ST_WRITE: begin
                grant     = 1'b1;
                mem_addr  = req_addr;
                mem_wdata = req_wdata;
                next_state = ST_IDLE;
            end

            ST_ERROR: begin
                fault     = 1'b1;
                next_state = ST_IDLE;
            end

            ST_LOCKED: begin
                // INTENTIONAL DEADLOCK:
                // No transition out of this state regardless of inputs
                fault = 1'b1;
                next_state = ST_LOCKED;
            end

            // INTENTIONALLY NO DEFAULT CASE
            // Incomplete state coverage vulnerability
        endcase
    end

endmodule
