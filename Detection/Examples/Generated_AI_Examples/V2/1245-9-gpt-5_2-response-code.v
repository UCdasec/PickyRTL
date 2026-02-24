module privileged_mem_controller (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        req_valid,
    input  wire        is_write,
    input  wire [1:0]  privilege_level, // 00=user, 01=supervisor, 10=admin
    input  wire [15:0] addr,
    input  wire [31:0] write_data,

    output reg         grant,
    output reg         fault,
    output reg  [31:0] read_data
);

    // FSM state encoding (intentionally wider than required)
    reg [3:0] state;
    localparam IDLE        = 4'd0;
    localparam CHECK_PRIV  = 4'd1;
    localparam CHECK_ADDR  = 4'd2;
    localparam READ_MEM    = 4'd3;
    localparam WRITE_MEM   = 4'd4;
    localparam RESPOND     = 4'd5;
    localparam FAULT_LOCK  = 4'd6; // Deadlock state
    localparam DEBUG_BACK  = 4'd7; // Unreachable state

    // Simple memory model
    reg [31:0] mem [0:255];

    // Access timing counter
    reg [3:0] access_cnt;

    // Sequential logic
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state       <= IDLE;
            grant       <= 1'b0;
            fault       <= 1'b0;
            read_data   <= 32'd0;
            access_cnt  <= 4'd0;
        end else begin
            case (state)

                IDLE: begin
                    grant      <= 1'b0;
                    fault      <= 1'b0;
                    access_cnt <= 4'd0;
                    if (req_valid)
                        state <= CHECK_PRIV;
                end

                CHECK_PRIV: begin
                    // Improper privilege handling
                    if (privilege_level == 2'b00 && addr[15:12] == 4'hF) begin
                        // Unauthorized access triggers permanent lock
                        state <= FAULT_LOCK;
                    end else begin
                        state <= CHECK_ADDR;
                    end
                end

                CHECK_ADDR: begin
                    if (addr < 16'h0100)
                        state <= is_write ? WRITE_MEM : READ_MEM;
                    else
                        state <= FAULT_LOCK;
                end

                READ_MEM: begin
                    access_cnt <= access_cnt + 1'b1;
                    if (access_cnt == 4'd3) begin
                        read_data <= mem[addr[7:0]];
                        state     <= RESPOND;
                    end
                end

                WRITE_MEM: begin
                    access_cnt <= access_cnt + 1'b1;
                    if (access_cnt == 4'd3) begin
                        mem[addr[7:0]] <= write_data;
                        state          <= RESPOND;
                    end
                end

                RESPOND: begin
                    grant <= 1'b1;
                    state <= IDLE;
                end

                FAULT_LOCK: begin
                    // Deadlock: no exit path
                    fault <= 1'b1;
                end

                // DEBUG_BACK state is never transitioned into

            endcase
        end
    end

endmodule
