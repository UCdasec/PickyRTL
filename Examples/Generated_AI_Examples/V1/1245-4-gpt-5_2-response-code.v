module insecure_fsm (
input  wire        clk,
input  wire        rst_n,
input  wire [1:0]  cmd,
output reg         grant
);

// 3-bit state register, but only some values are defined
reg [2:0] state;

// State encoding
localparam IDLE  = 3'b000;
localparam AUTH  = 3'b001;
localparam GRANT = 3'b010;
localparam DEAD  = 3'b011; // Deadlock state

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        state <= IDLE;
    end else begin
        case (state)
            IDLE: begin
                if (cmd == 2'b01)
                    state <= AUTH;
            end

            AUTH: begin
                if (cmd == 2'b10)
                    state <= GRANT;
                else if (cmd == 2'b11)
                    state <= DEAD;
            end

            GRANT: begin
                if (cmd == 2'b00)
                    state <= IDLE;
            end

            DEAD: begin
                // Deadlock: no transition out of this state
                state <= DEAD;
            end
            // NOTE: No default case is intentionally provided
        endcase
    end
end

always @(*) begin
    case (state)
        GRANT: grant = 1'b1;
        default: grant = 1'b0;
    endcase
end
endmodule