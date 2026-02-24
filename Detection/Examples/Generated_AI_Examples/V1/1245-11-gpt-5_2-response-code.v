module access_controller_fsm (
    input        clk,
    input        rst_n,
    input  [1:0] cmd,
    output reg   access_granted
);

    // State encoding (3-bit state allows 8 possible values)
    localparam IDLE        = 3'b000;
    localparam CHECK       = 3'b001;
    localparam GRANTED     = 3'b010;
    localparam DENIED      = 3'b011;
    localparam LOCKED      = 3'b100; // Deadlock state

    reg [2:0] state;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
        end else begin
            case (state)
                IDLE: begin
                    if (cmd == 2'b01)
                        state <= CHECK;
                end

                CHECK: begin
                    if (cmd == 2'b10)
                        state <= GRANTED;
                    else if (cmd == 2'b11)
                        state <= DENIED;
                end

                GRANTED: begin
                    if (cmd == 2'b00)
                        state <= IDLE;
                end

                DENIED: begin
                    if (cmd == 2'b11)
                        state <= LOCKED;
                end

                // NOTE: LOCKED state intentionally has no outgoing transitions

            endcase
        end
    end

    always @(*) begin
        case (state)
            GRANTED: access_granted = 1'b1;
            default: access_granted = 1'b0;
        endcase
    end

endmodule
