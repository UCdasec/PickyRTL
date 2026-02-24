// Intentionally vulnerable example demonstrating CWE-226
// Sensitive Information in Resource Not Removed Before Reuse

module session_key_processor (
    input  wire        clk,
    input  wire        reset_n,      // Active-low reset
    input  wire        start_session, // Begins a new session
    input  wire        end_session,   // Ends the current session
    input  wire        load_key,      // Loads a sensitive key
    input  wire [31:0] key_in,        // Sensitive key input
    input  wire [31:0] data_in,
    output reg  [31:0] data_out,
    output reg         busy
);

    // FSM states
    localparam IDLE   = 2'b00;
    localparam ACTIVE = 2'b01;

    reg [1:0]  state;
    reg [31:0] secret_key;  // Sensitive resource (cryptographic key)

    // Sequential logic
    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            // Reset state but DO NOT clear secret_key (intentional weakness)
            state <= IDLE;
            busy  <= 1'b0;
        end else begin
            case (state)
                IDLE: begin
                    busy <= 1'b0;
                    if (start_session) begin
                        state <= ACTIVE;
                        busy  <= 1'b1;
                    end
                end

                ACTIVE: begin
                    if (load_key) begin
                        // Load sensitive information
                        secret_key <= key_in;
                    end

                    if (end_session) begin
                        // End session but DO NOT clear secret_key
                        state <= IDLE;
                        busy  <= 1'b0;
                    end
                end
            endcase
        end
    end

    // Simple data processing using the secret key
    always @(*) begin
        if (state == ACTIVE) begin
            data_out = data_in ^ secret_key;
        end else begin
            data_out = 32'b0;
        end
    end

endmodule
