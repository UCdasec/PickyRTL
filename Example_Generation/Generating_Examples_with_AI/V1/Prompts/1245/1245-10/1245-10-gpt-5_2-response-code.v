module access_fsm (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        req,
    input  wire        auth_ok,
    output reg         grant
);

    // State encoding (3-bit state register)
    localparam IDLE   = 3'd0;
    localparam AUTH   = 3'd1;
    localparam GRANT  = 3'd2;
    localparam LOCK   = 3'd3;  // Deadlock state
    localparam SECRET = 3'd5;  // Unreachable state

    reg [2:0] state;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            grant <= 1'b0;
        end else begin
            case (state)
                IDLE: begin
                    grant <= 1'b0;
                    if (req)
                        state <= AUTH;
                end

                AUTH: begin
                    if (auth_ok)
                        state <= GRANT;
                    else
                        state <= LOCK;
                end

                GRANT: begin
                    grant <= 1'b1;
                    if (!req)
                        state <= IDLE;
                end

                LOCK: begin
                    // Deadlock: no transition out of LOCK
                    grant <= 1'b0;
                    state <= LOCK;
                end

                // NOTE: No handling for SECRET or other state values
            endcase
        end
    end

endmodule
