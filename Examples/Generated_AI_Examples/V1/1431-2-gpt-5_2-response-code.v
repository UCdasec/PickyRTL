module insecure_block_cipher (
    input  wire        clk,
    input  wire        reset_n,
    input  wire        start,
    input  wire [31:0] plaintext,
    input  wire [31:0] key,
    output reg  [31:0] ciphertext,
    output reg  [31:0] debug_state,   // <-- Leaks intermediate cryptographic state
    output reg         done
);

    // Internal round state
    reg [31:0] round_state;
    reg [1:0]  round_counter;

    // Simple rotate-left function
    function [31:0] rotl1;
        input [31:0] data;
        begin
            rotl1 = {data[30:0], data[31]};
        end
    endfunction

    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            round_state   <= 32'd0;
            round_counter <= 2'd0;
            ciphertext    <= 32'd0;
            debug_state   <= 32'd0;
            done          <= 1'b0;
        end else begin
            if (start) begin
                // Initialize encryption
                round_state   <= plaintext ^ key;
                round_counter <= 2'd0;
                done          <= 1'b0;
            end else if (!done) begin
                // Perform a simple multi-round "encryption"
                round_state <= rotl1(round_state) ^ key;
                round_counter <= round_counter + 1'b1;

                // *** CWE-1431 VULNERABILITY ***
                // Intermediate cryptographic state is driven directly to output
                debug_state <= round_state;

                if (round_counter == 2'd3) begin
                    ciphertext <= round_state;
                    done <= 1'b1;
                end
            end
        end
    end

endmodule
