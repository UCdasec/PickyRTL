module shared_buffer_controller (
    input  wire        clk,
    input  wire        rst_n,

    // Control signals
    input  wire        secure_mode,     // 1 = secure capture, 0 = public access
    input  wire        write_enable,
    input  wire [7:0]  data_in,          // Could be secret or non-secret
    input  wire [3:0]  addr,

    output reg  [7:0]  data_out
);

    // Shared memory buffer reused across modes
    reg [7:0] buffer [0:15];

    reg secure_active;

    integer i;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            // Reset clears control state only
            secure_active <= 1'b0;
            data_out      <= 8'd0;

            // NOTE: buffer contents are intentionally NOT cleared
        end else begin
            secure_active <= secure_mode;

            // Write operation
            if (write_enable) begin
                buffer[addr] <= data_in;
            end

            // Read operation
            data_out <= buffer[addr];
        end
    end

endmodule
