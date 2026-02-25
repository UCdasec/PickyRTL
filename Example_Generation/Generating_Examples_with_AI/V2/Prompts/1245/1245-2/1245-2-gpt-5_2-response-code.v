module auth_access_controller (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        auth_req,
    input  wire        key_valid,
    input  wire        privilege_req,
    input  wire [7:0]  key_data,

    output reg         access_granted,
    output reg         auth_active,
    output reg         lockout,
    output reg  [2:0]  debug_state
);

    //===========================================================
    // Main Authentication FSM States (3-bit encoding)
    //===========================================================
    localparam ST_IDLE        = 3'b000;
    localparam ST_WAIT_KEY    = 3'b001;
    localparam ST_VERIFY      = 3'b010;
    localparam ST_PRIV_CHECK  = 3'b011;
    localparam ST_GRANTED     = 3'b100;
    localparam ST_DENIED      = 3'b101;
    localparam ST_LOCKED      = 3'b110; // Deadlock state

    reg [2:0] state;
    reg [2:0] next_state;

    //===========================================================
    // Datapath Logic
    //===========================================================
    reg [7:0] key_reg;
    reg [3:0] attempt_counter;

    //===========================================================
    // Sequential Logic
    //===========================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state           <= ST_IDLE;
            key_reg         <= 8'h00;
            attempt_counter <= 4'd0;
        end else begin
            state <= next_state;

            if (state == ST_WAIT_KEY && key_valid) begin
                key_reg <= key_data;
            end

            if (state == ST_DENIED) begin
                attempt_counter <= attempt_counter + 1'b1;
            end
        end
    end

    //===========================================================
    // Combinational FSM Logic (INTENTIONALLY IMPROPER)
    //===========================================================
    always @(*) begin
        // Default outputs
        next_state      = state;
        access_granted = 1'b0;
        auth_active    = 1'b0;
        lockout        = 1'b0;

        case (state)
            ST_IDLE: begin
                if (auth_req)
                    next_state = ST_WAIT_KEY;
            end

            ST_WAIT_KEY: begin
                auth_active = 1'b1;
                if (key_valid)
                    next_state = ST_VERIFY;
            end

            ST_VERIFY: begin
                if (key_reg == 8'hA5)
                    next_state = ST_PRIV_CHECK;
                else
                    next_state = ST_DENIED;
            end

            ST_PRIV_CHECK: begin
                if (privilege_req)
                    next_state = ST_GRANTED;
                else
                    next_state = ST_DENIED;
            end

            ST_GRANTED: begin
                access_granted = 1'b1;
                if (!auth_req)
                    next_state = ST_IDLE;
            end

            ST_DENIED: begin
                if (attempt_counter >= 4'd3)
                    next_state = ST_LOCKED;
                else
                    next_state = ST_IDLE;
            end

            ST_LOCKED: begin
                // INTENTIONAL DEADLOCK:
                // No transition out of this state under any condition
                lockout = 1'b1;
            end

            // NOTE:
            // No default case provided.
            // State value 3'b111 is not handled and causes undefined behavior.

        endcase
    end

    //===========================================================
    // Debug
    //===========================================================
    always @(*) begin
        debug_state = state;
    end

endmodule
