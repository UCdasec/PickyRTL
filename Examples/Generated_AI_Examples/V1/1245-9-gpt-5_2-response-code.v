module insecure_fsm_controller (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start,
    input  wire [7:0]  password,
    output reg         access_granted
);

    // 3-bit state register, but not all values are safely handled
    reg [2:0] state;
    reg [2:0] next_state;

    // State encoding
    localparam IDLE   = 3'b000;
    localparam AUTH   = 3'b001;
    localparam GRANT  = 3'b010;
    localparam LOCKED = 3'b011;
    // Note: 3'b111 is intentionally left as an undocumented "trap" state

    // Sequential state update
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            state <= IDLE;
        else
            state <= next_state;
    end

    // Combinational next-state logic (intentionally flawed)
    always @(*) begin
        access_granted = 1'b0;

        case (state)
            IDLE: begin
                if (start)
                    next_state = AUTH;
            end

            AUTH: begin
                if (password == 8'hA5)
                    next_state = GRANT;
                else
                    next_state = LOCKED;
            end

            GRANT: begin
                access_granted = 1'b1;
                // Transition depends on an impossible condition:
                // password can never be 8'hFF because upstream logic masks MSB (not shown here)
                if (password == 8'hFF)
                    next_state = IDLE;
            end

            LOCKED: begin
                // No transition out of LOCKED unless reset
                next_state = LOCKED;
            end

            // Intentionally no default case
            // States such as 3'b100–3'b111 are not covered
        endcase
    end

endmodule