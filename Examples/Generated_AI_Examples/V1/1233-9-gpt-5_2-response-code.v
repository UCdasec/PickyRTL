module insecure_key_ctrl (
    input  wire        clk,
    input  wire        rst_n,

    // Simple register write interface
    input  wire        wr_en,
    input  wire [3:0]  wr_addr,
    input  wire [31:0] wr_data,

    // Outputs for observation
    output reg  [31:0] secure_key,
    output reg         debug_enable,
    output reg         lock_bit
);

    // Address map
    localparam ADDR_KEY   = 4'h0;
    localparam ADDR_CTRL  = 4'h1;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            secure_key   <= 32'h00000000;
            debug_enable <= 1'b0;
            lock_bit     <= 1'b0;
        end else begin
            if (wr_en) begin
                case (wr_addr)

                    // SECURITY-SENSITIVE REGISTER
                    // Intended to be protected by lock_bit
                    ADDR_KEY: begin
                        // VULNERABILITY:
                        // secure_key can be overwritten regardless of lock_bit
                        secure_key <= wr_data;
                    end

                    // Control register
                    ADDR_CTRL: begin
                        // debug_enable is (incorrectly) protected by lock_bit
                        if (!lock_bit) begin
                            debug_enable <= wr_data[1];
                        end

                        // lock_bit itself is writable at any time
                        lock_bit <= wr_data[0];
                    end

                    default: begin
                        // no-op
                    end

                endcase
            end
        end
    end

endmodule
