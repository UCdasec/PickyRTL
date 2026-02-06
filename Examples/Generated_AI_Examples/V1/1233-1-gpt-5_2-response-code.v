module insecure_security_reg (
    input  wire        clk,
    input  wire        reset_n,

    input  wire        write_en,
    input  wire [1:0]  addr,
    input  wire [31:0] write_data,

    output reg  [31:0] security_key,
    output reg         lock_bit
);

    // Address map
    localparam ADDR_KEY  = 2'b00;
    localparam ADDR_LOCK = 2'b01;

    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            security_key <= 32'h00000000;
            lock_bit     <= 1'b0;
        end else if (write_en) begin
            case (addr)
                ADDR_KEY: begin
                    // SECURITY-SENSITIVE REGISTER
                    // VulnerABILITY: write allowed regardless of lock_bit
                    security_key <= write_data;
                end

                ADDR_LOCK: begin
                    // Lock bit can be set by software
                    lock_bit <= write_data[0];
                end

                default: begin
                    // No action
                end
            endcase
        end
    end

endmodule
