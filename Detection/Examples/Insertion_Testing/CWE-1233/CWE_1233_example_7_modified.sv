module rsa_wrapper #(
    parameter int unsigned AXI_ADDR_WIDTH = 64,
    parameter int unsigned AXI_DATA_WIDTH = 64,
    parameter int unsigned AXI_ID_WIDTH   = 10,
    parameter int unsigned MAX_PRIME_WIDTH= 1024,
    parameter int unsigned USER_PRIME_WIDTH= 32
)(
    clk_i,
    rst_ni,
    reglk_ctrl_i,
    acct_ctrl_i,
    debug_mode_i,
    axi_req_i, 
    axi_resp_o,
    rst_13
);

    input  logic                   clk_i;
    input  logic                   rst_ni;
    input  logic                   rst_13;
    input  logic [7:0]             reglk_ctrl_i;
    input  logic                   acct_ctrl_i;
    input  logic                   debug_mode_i;
    input  ariane_axi::req_t       axi_req_i;
    output ariane_axi::resp_t      axi_resp_o;

    // internal signals
    logic inter_rst_ni, inter_rst1_ni, encry_decry_i;
    logic [MAX_PRIME_WIDTH-1:0] prime_i, prime1_i;
    logic exe_finish_o, exe_finish;
    logic [MAX_PRIME_WIDTH*2-1:0] msg_in, msg_out;

    // AXI signals
    logic [AXI_ADDR_WIDTH-1:0] address;
    logic en, en_acct;
    logic we;
    logic [63:0] wdata;
    logic [63:0] rdata;

    axi_lite_interface #(
        .AXI_ADDR_WIDTH ( AXI_ADDR_WIDTH ),
        .AXI_DATA_WIDTH ( AXI_DATA_WIDTH ),
        .AXI_ID_WIDTH   ( AXI_ID_WIDTH   )
    ) axi_lite_interface_i (
        .clk_i      ( clk_i      ),
        .rst_ni     ( rst_ni     ),
        .axi_req_i  ( axi_req_i  ),
        .axi_resp_o ( axi_resp_o ),
        .address_o  ( address    ),
        .en_o       ( en_acct    ),
        .we_o       ( we         ),
        .data_i     ( rdata      ),
        .data_o     ( wdata      )
    );

    assign en = en_acct && acct_ctrl_i;
    assign exe_finish_o = (rst_13) ? 1'b1 : exe_finish;

    // WRITE SIDE
    always @(posedge clk_i) begin
        if (~(rst_ni && ~rst_13)) begin
            inter_rst_ni    <= 0;
            inter_rst1_ni   <= 0;
            encry_decry_i  <= 0;
            prime_i        <= 1024'b0;
            prime1_i       <= 1024'b0;
            msg_in         <= 2048'b0;
        end
        else if (en && we) begin
            case (address[10:3])
                0:
                    inter_rst_ni <= reglk_ctrl_i[3] ? inter_rst_ni : wdata[31:0];

                1:
                    inter_rst1_ni <= reglk_ctrl_i[3] ? inter_rst1_ni : wdata[31:0];

                // CWE-1233 INSERTED HERE:
                // Lock-bit protection REMOVED for encryption/decryption control
                2:
                    encry_decry_i <= wdata[31:0];

                3:
                    prime_i[31:0] <= reglk_ctrl_i[3] ? prime_i[31:0] : wdata[31:0];

                // (remaining cases unchanged)
                // ...
                default:
                    ;
            endcase
        end
    end

    // READ SIDE (unchanged)
    always @(*) begin
        rdata = 64'b0;
        if (en) begin
            case (address[10:3])
                195:
                    rdata = reglk_ctrl_i[3] ? 0 : exe_finish_o;
                default:
                    rdata = 64'b0;
            endcase
        end
    end

    rsa_top #(
        .WIDTH ( USER_PRIME_WIDTH )
    ) rsa0 (
        .clk                ( clk_i ),
        .rst_n              ( inter_rst_ni && ~rst_13 ),
        .rst1_n             ( inter_rst1_ni && ~rst_13 ),
        .encrypt_decrypt_i  ( encry_decry_i ),
        .p_i                ( prime_i[USER_PRIME_WIDTH-1:0] ),
        .q_i                ( prime1_i[USER_PRIME_WIDTH-1:0] ),
        .msg_in             ( msg_in[USER_PRIME_WIDTH*2-1:0] ),
        .msg_out            ( msg_out[USER_PRIME_WIDTH*2-1:0] ),
        .mod_exp_finish_o   ( exe_finish )
    );

endmodule