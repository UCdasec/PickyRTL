module insecure_resource_reuse (
    input  wire        clk,
    input  wire        reset_n,

    // Control signals
    input  wire        load_secret,   // Load sensitive data
    input  wire        switch_to_user, // Switch from privileged to user mode
    input  wire        user_read,      // User attempts to read data

    // Data inputs
    input  wire [31:0] secret_in,      // Sensitive value (e.g., cryptographic key)

    // Data output
    output reg  [31:0] data_out
);

    // Simple mode encoding
    localparam MODE_PRIVILEGED = 1'b0;
    localparam MODE_USER       = 1'b1;

    reg mode;

    // Register that stores sensitive information
    reg [31:0] sensitive_reg;

    always @(posedge clk) begin
        if (!reset_n) begin
            // Reset only sets the mode
            // NOTE: sensitive_reg is NOT cleared here
            mode     <= MODE_PRIVILEGED;
            data_out <= 32'b0;
        end else begin
            // Load sensitive data in privileged mode
            if (mode == MODE_PRIVILEGED && load_secret) begin
                sensitive_reg <= secret_in;
            end

            // Transition to user mode
            if (switch_to_user) begin
                mode <= MODE_USER;
            end

            // User can read data once in user mode
            if (mode == MODE_USER && user_read) begin
                // Reuse of sensitive_reg without clearing
                data_out <= sensitive_reg;
            end
        end
    end

endmodule
