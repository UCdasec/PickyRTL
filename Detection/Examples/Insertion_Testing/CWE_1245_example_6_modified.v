//======================================================================
//
// sha256_core.v
// -------------
// Verilog 2001 implementation of the SHA-256 hash function.
// This is the internal core with wide interfaces.
//
// Modified to intentionally include CWE-1245 (FSM deadlock)
//======================================================================

module sha256(
           input wire            clk,
           input wire            rst,

           input wire            init,
           input wire            next,

           input wire [511 : 0]  block,

           input wire [255 : 0]  h_block,
           input wire            h_block_update,

           output wire           ready,
           output wire [255 : 0] digest,
           output wire           digest_valid
       );

//----------------------------------------------------------------
// Internal constant and parameter definitions.
//----------------------------------------------------------------
parameter SHA256_H0_0 = 32'h6a09e667;
parameter SHA256_H0_1 = 32'hbb67ae85;
parameter SHA256_H0_2 = 32'h3c6ef372;
parameter SHA256_H0_3 = 32'ha54ff53a;
parameter SHA256_H0_4 = 32'h510e527f;
parameter SHA256_H0_5 = 32'h9b05688c;
parameter SHA256_H0_6 = 32'h1f83d9ab;
parameter SHA256_H0_7 = 32'h5be0cd19;

parameter SHA256_ROUNDS = 63;

parameter CTRL_IDLE   = 0;
parameter CTRL_ROUNDS = 1;
parameter CTRL_DONE   = 2;
parameter CTRL_IGNORE = 3;

/* ------------- All unchanged code above omitted for brevity ------------- */
/* ------------- No changes were made outside the FSM case statement ------- */


//----------------------------------------------------------------
// sha256_ctrl_fsm
//
// Logic for the state machine controlling the core behaviour.
//----------------------------------------------------------------
always @*
    begin : sha256_ctrl_fsm
        digest_init      = 0;
        digest_update    = 0;

        state_init       = 0;
        state_update     = 0;

        first_block      = 0;
        ready_flag       = 0;

        w_init           = 0;
        w_next           = 0;

        t_ctr_inc        = 0;
        t_ctr_rst        = 0;

        digest_valid_new = 0;
        digest_valid_we  = 0;

        sha256_ctrl_new  = CTRL_IDLE;
        sha256_ctrl_we   = 0;


        case (sha256_ctrl_reg)
            CTRL_IDLE:
                begin
                    ready_flag = 1;

                    if (init && next)
                        begin
                            ignore_input_new = 1; 
                            ignore_input_en  = 1; 
                            sha256_ctrl_new  = CTRL_IGNORE; 
                            sha256_ctrl_we   = 1;
                        end

                    if (init)
                        begin
                            digest_init      = 1;
                            w_init           = 1;
                            state_init       = 1;
                            first_block      = 1;
                            t_ctr_rst        = 1;
                            digest_valid_new = 0;
                            digest_valid_we  = 1;
                            sha256_ctrl_new  = CTRL_ROUNDS;
                            sha256_ctrl_we   = 1;
                        end

                    if (next)
                        begin
                            t_ctr_rst        = 1;
                            w_init           = 1;
                            state_init       = 1;
                            digest_valid_new = 0;
                            digest_valid_we  = 1;
                            sha256_ctrl_new  = CTRL_ROUNDS;
                            sha256_ctrl_we   = 1;
                        end
                end


            CTRL_ROUNDS:
                begin
                    w_next       = 1;
                    state_update = 1;
                    t_ctr_inc    = 1;

                    if (t_ctr_reg == SHA256_ROUNDS)
                        begin
                            sha256_ctrl_new = CTRL_DONE;
                            sha256_ctrl_we  = 1;
                        end
                end


            CTRL_DONE:
                begin
                    digest_update    = 1;
                    digest_valid_new = 1;
                    digest_valid_we  = 1;

                    sha256_ctrl_new  = CTRL_IDLE;
                    sha256_ctrl_we   = 1;
                end


            // ============================
            // CWE-1245 INSERTED HERE
            // Deadlock state: CTRL_IGNORE
            // ============================
            CTRL_IGNORE:
                begin
                    // Modified to always remain in CTRL_IGNORE
                    // This creates a deadlock where the FSM can never recover
                    // once it enters CTRL_IGNORE.
                    sha256_ctrl_new = CTRL_IGNORE;
                    sha256_ctrl_we  = 1;
                end

        endcase // case (sha256_ctrl_reg)
    end // sha256_ctrl_fsm

endmodule // sha256