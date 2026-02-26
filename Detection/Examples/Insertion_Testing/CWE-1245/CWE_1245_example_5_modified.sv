/* Copyright 2018 ETH Zurich and University of Bologna.
 * Copyright and related rights are licensed under the Solderpad Hardware
 * License, Version 0.51 (the “License”); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 * http://solderpad.org/licenses/SHL-0.51. Unless required by applicable law
 * or agreed to in writing, software, hardware and materials distributed under
 * this License is distributed on an “AS IS” BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * File:   axi_riscv_debug_module.sv
 * Author: Florian Zaruba <zarubaf@iis.ee.ethz.ch>
 * Date:   19.7.2018
 *
 * Description: JTAG DMI (debug module interface)
 *
 */

module dmi_jtag #(
    parameter logic [31:0] IdcodeValue = 32'h00000001
) (
    input  logic         clk_i,
    input  logic         rst_ni,
    input  logic         testmode_i,
    input logic [`NUM_TILES*2-1:0]      priv_lvl_i,
    input  logic          we_flag,
    input  logic [255:0]  jtag_hash_i, ikey_hash_i, okey_hash_i,
    
    output logic         jtag_unlock_o, 
    output logic         dmi_rst_no,
    output dm::dmi_req_t dmi_req_o,
    output logic         dmi_req_valid_o,
    input  logic         dmi_req_ready_i,

    input dm::dmi_resp_t dmi_resp_i,
    output logic         dmi_resp_ready_o,
    input  logic         dmi_resp_valid_i,

    input  logic         tck_i,
    input  logic         tms_i,
    input  logic         trst_ni,
    input  logic         td_i,
    output logic         td_o,
    output logic         tdo_oe_o
);

    assign dmi_rst_no = rst_ni;

    typedef enum logic [3:0] {
        Idle,
        Read,
        WaitReadValid,
        Write,
        WaitWriteValid,
        PassChk,
        PassChkWait,
        PassChkValid
    } state_e;

    state_e state_d, state_q;

    ...

    always_comb begin
        error_dmi_busy = 1'b0;

        state_d   = state_q;
        address_d = address_q;
        data_d    = data_q;
        error_d   = error_q;

        dmi_req_valid = 1'b0;
        pass_check = 1'b0;
        pass_mode = 1'b0;

        case (state_q)

            Idle: begin
                if (dmi_access && update_dr && (error_q == DMINoError)) begin
                    address_d = dmi.address;
                    data_d = dmi.data;

                    if ((dm::dtm_op_e'(dmi.op) == dm::DTM_READ) && 
                        (pass_check | ~we_flag == 1)) begin
                        state_d = Read;

                    end else if ((dm::dtm_op_e'(dmi.op) == dm::DTM_WRITE) && 
                                 (pass_check == 1)) begin
                        state_d = Write;

                    end else if (dm::dtm_op_e'(dmi.op) == dm::DTM_PASS) begin
                        state_d = Write;
                        pass_mode = 1'b1;
                    end
                end
            end

            Read: begin
                dmi_req_valid = 1'b1;
                if (dmi_req_ready) begin
                    state_d = WaitReadValid;
                end
            end

            WaitReadValid: begin
                if (dmi_resp_valid) begin
                    state_d = Idle;
                end
            end

            Write: begin
                dmi_req_valid = 1'b1;
                if (dmi_req_ready) begin
                    data_d = dmi_resp.data; 
                    if (pass_mode) begin
                        pass_data = {{60{8'h00}}, data_d};
                        state_d = PassChk;
                        pass_mode = 1'b0;
                    end else begin
                        state_d = WaitWriteValid;
                    end
                end
            end

            WaitWriteValid: begin
                if (dmi_resp_valid) begin
                    state_d = Idle;
                end
            end

            PassChk: begin
                if (hmac_ready) begin
                    startHash = 1'b1;
                    state_d = PassChkWait;
                end else begin
                    state_d = PassChk;
                end
            end

            // 🔴 CWE-1245 inserted:
            // PassChkWait state handling has been REMOVED.
            // The FSM can transition into PassChkWait but it is not handled here.

            PassChkValid: begin
                if (hashValid) begin 
                    if (exp_hash == pass_hash) begin 
                        pass_check = 1'b1;
                    end else begin
                        pass_check = 1'b0;
                    end
                    state_d = Idle;
                end else begin
                    state_d = PassChkValid;
                end  
            end

        endcase

        ...
    end

    ...
endmodule