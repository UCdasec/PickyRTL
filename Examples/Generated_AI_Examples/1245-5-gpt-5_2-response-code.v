module door_fsm (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        card_valid,
    input  wire        open_request,
    output reg         door_open
);

    // 3-bit state register allows 8 possible values,
    // but only a subset are properly handled
    reg [2:0] state;

    // State encoding
    localparam IDLE  = 3'b000;
    localparam AUTH  = 3'b001;
    localparam OPEN  = 3'b010;
    localparam ERROR = 3'b011; // deadlock state

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            door_open <= 1'b0;
        end else begin
            case (state)
                IDLE: begin
                    door_open <= 1'b0;
                    if (card_valid)
                        state <= AUTH;
                end

                AUTH: begin
                    if (open_request)
                        state <= OPEN;
                end

                OPEN: begin
                    door_open <= 1'b1;
                    // Return to IDLE when card is removed
                    if (!card_valid)
                        state <= IDLE;
                end

                ERROR: begin
                    // Deadlock: no exit condition
                    door_open <= 1'b0;
                    state <= ERROR;
                end
                // NOTE: No default case provided
            endcase
        end
    end

endmodule
