module access_controller_fsm (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        req,        // request to access
    input  wire        auth_ok,    // authentication result
    input  wire        fault,      // injected fault condition
    output reg         grant
);

    // FSM state encoding (3-bit state register)
    reg [2:0] state;

    localparam IDLE      = 3'b000;
    localparam AUTH      = 3'b001;
    localparam GRANTED   = 3'b010;
    localparam LOCKED    = 3'b011;
    localparam ERROR     = 3'b100;  // deadlock state
    localparam UNUSED    = 3'b101;  // unreachable state

    // State transition and output logic
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
                    if (fault)
                        state <= ERROR;     // transition into deadlock state
                    else if (auth_ok)
                        state <= GRANTED;
                    else
                        state <= LOCKED;
                end

                GRANTED: begin
                    grant <= 1'b1;
                    if (!req)
                        state <= IDLE;
                end

                LOCKED: begin
                    grant <= 1'b0;
                    if (!req)
                        state <= IDLE;
                end

                ERROR: begin
                    // Deadlock: no transition out of ERROR
                    grant <= 1'b0;
                end
                // NOTE: No default case and UNUSED state is never handled
            endcase
        end
    end

endmodule