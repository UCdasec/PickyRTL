// Wrapper for sha_256

module hmac_wrapper #(
    parameter int unsigned AXI_ADDR_WIDTH = 64,
    parameter int unsigned AXI_DATA_WIDTH = 64,
    parameter int unsigned AXI_ID_WIDTH   = 10
)(
           clk_i,
           rst_ni,
           reglk_ctrl_i,
           acct_ctrl_i,
           debug_mode_i,
           axi_req_i, 
           axi_resp_o,
           rst_4
       );

    input  logic                   clk_i;
    input  logic                   rst_ni;
    input logic [7 :0]             reglk_ctrl_i; // register lock values
    input logic                    acct_ctrl_i;
    input logic                    debug_mode_i;
    input  ariane_axi::req_t       axi_req_i;
    output ariane_axi::resp_t      axi_resp_o;

    input logic rst_4;

reg newMessage_r, startHash_r;
logic startHash;
logic newMessage;
logic key_hash_bypass; 
logic [31:0] data [0:15];
logic [31:0] key0 [0:7];
logic [31:0] ikey_hash_bytes [0:7];
logic [31:0] okey_hash_bytes [0:7];

logic [511:0] bigData; 
logic [255:0] hash;
logic ready;
logic hashValid;
logic [256-1:0] key, ikey_hash, okey_hash;

logic [AXI_ADDR_WIDTH-1:0] address;
logic                      en, en_acct;
logic                      we;
logic [63:0] wdata;
logic [63:0] rdata;

assign key    = debug_mode_i ? 256'b0 : {key0[0], key0[1], key0[2], key0[3], key0[4], key0[5], key0[6], key0[7]}; 
assign ikey_hash = {ikey_hash_bytes[0], ikey_hash_bytes[1], ikey_hash_bytes[2], ikey_hash_bytes[3], ikey_hash_bytes[4], ikey_hash_bytes[5], ikey_hash_bytes[6], ikey_hash_bytes[7]}; 
assign okey_hash = debug_mode_i ? 256'b0 : {okey_hash_bytes[0], okey_hash_bytes[1], okey_hash_bytes[2], okey_hash_bytes[3], okey_hash_bytes[4], okey_hash_bytes[5], okey_hash_bytes[6], okey_hash_bytes[7]}; 

assign bigData = {data[15], data[14], data[13], data[12], data[11], data[10], data[9], data[8],
                  data[7], data[6], data[5], data[4], data[3], data[2], data[1], data[0]};

axi_lite_interface #(
    .AXI_ADDR_WIDTH ( AXI_ADDR_WIDTH ),
    .AXI_DATA_WIDTH ( AXI_DATA_WIDTH ),
    .AXI_ID_WIDTH   ( AXI_ID_WIDTH    )
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

always @(posedge clk_i) begin
    if(~(rst_ni && ~rst_4)) begin
        startHash_r <= 1'b0;
        newMessage_r <= 1'b0;
    end else begin
        startHash_r  <= startHash;
        newMessage_r <= newMessage;
    end
end

// Write side
always @(posedge clk_i) begin
    if(~(rst_ni && ~rst_4)) begin
        startHash <= 0;
        newMessage <= 0;

        data[0]  <= 0;  data[1]  <= 0;  data[2]  <= 0;  data[3]  <= 0;
        data[4]  <= 0;  data[5]  <= 0;  data[6]  <= 0;  data[7]  <= 0;
        data[8]  <= 0;  data[9]  <= 0;  data[10] <= 0;  data[11] <= 0;
        data[12] <= 0;  data[13] <= 0;  data[14] <= 0;  data[15] <= 0;

        // CWE-226 INSERTED: sensitive key material is NOT cleared on reset
        key0[0] <= key0[0];
        key0[1] <= key0[1];
        key0[2] <= key0[2];
        key0[3] <= key0[3];
        key0[4] <= key0[4];
        key0[5] <= key0[5];
        key0[6] <= key0[6];
        key0[7] <= key0[7];

        ikey_hash_bytes[0] <= ikey_hash_bytes[0];
        ikey_hash_bytes[1] <= ikey_hash_bytes[1];
        ikey_hash_bytes[2] <= ikey_hash_bytes[2];
        ikey_hash_bytes[3] <= ikey_hash_bytes[3];
        ikey_hash_bytes[4] <= ikey_hash_bytes[4];
        ikey_hash_bytes[5] <= ikey_hash_bytes[5];
        ikey_hash_bytes[6] <= ikey_hash_bytes[6];
        ikey_hash_bytes[7] <= ikey_hash_bytes[7];

        okey_hash_bytes[0] <= okey_hash_bytes[0];
        okey_hash_bytes[1] <= okey_hash_bytes[1];
        okey_hash_bytes[2] <= okey_hash_bytes[2];
        okey_hash_bytes[3] <= okey_hash_bytes[3];
        okey_hash_bytes[4] <= okey_hash_bytes[4];
        okey_hash_bytes[5] <= okey_hash_bytes[5];
        okey_hash_bytes[6] <= okey_hash_bytes[6];
        okey_hash_bytes[7] <= okey_hash_bytes[7];

        key_hash_bypass <= 0;
    end
    else if(en && we) begin
        case(address[9:3])
            0: begin
                startHash <= reglk_ctrl_i[1] ? startHash : wdata[0];
                newMessage <= reglk_ctrl_i[1] ? newMessage : wdata[1];
                key_hash_bypass <= reglk_ctrl_i[1] ? key_hash_bypass : wdata[2];
            end
            default: ;
        endcase
    end
end

hmac hmac(
    .clk_i(clk_i),
    .rst_ni(rst_ni && ~rst_4),
    .init_i(startHash && ~startHash_r),
    .key_i(key),
    .ikey_hash_i(ikey_hash), 
    .okey_hash_i(okey_hash), 
    .key_hash_bypass_i(key_hash_bypass),
    .message_i(bigData),
    .hash_o(hash),
    .ready_o(ready),
    .hash_valid_o(hashValid)   
);

endmodule