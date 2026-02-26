module aes_192 (clk, start, state, key, inter_state, out, out_valid);
input          clk;
input          start;
input  [127:0] state;
input  [191:0] key;
output [127:0] inter_state;
output [127:0] out;
output         out_valid;
reg    [127:0] out;
reg    [127:0] next_out;
reg    [127:0] s0;
reg    [191:0] k0;
wire   [127:0] s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12;
wire   [191:0] k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11;
wire   [127:0] k0b, k1b, k2b, k3b, k4b, k5b, k6b, k7b, k8b, k9b, k10b, k11b;

reg start_r;
always @(posedge clk)
    begin
        start_r <= start;
    end

assign inter_state = s1;
wire start_posedge = start & ~start_r;
reg [4:0] validCounter;

always @(posedge clk)
    begin
        case(validCounter)
            1  : next_out <= s12;
            2  : next_out <= s11;
            3  : next_out <= s10;
            4  : next_out <= s9;
            5  : next_out <= s8;
            6  : next_out <= s7;
            7  : next_out <= s6;
            8  : next_out <= s5;
            9  : next_out <= s4;
            10 : next_out <= s3;
            11 : next_out <= s2;
            12 : next_out <= s1;
            default : next_out <= s12;
        endcase
    end

always @ (posedge clk)
    begin
        if(start_posedge)
            begin
                s0 <= state ^ key[191:64];
                k0 <= key;
                validCounter <= 25;
            end
        else if(~out_valid)
            begin
                validCounter <= validCounter - 1;
            end
    end

assign out_valid = (validCounter == 0);

/* CWE-1431 INSERTION:
 * Drive intermediate cryptographic state to output even when out_valid is low
 */
assign out = next_out;

expand_key_type_D_192  a0 (clk, k0, 8'h1,   k1,  k0b);
expand_key_type_B_192  a1 (clk, k1,         k2,  k1b);
expand_key_type_A_192  a2 (clk, k2, 8'h2,   k3,  k2b);
expand_key_type_C_192  a3 (clk, k3, 8'h4,   k4,  k3b);
expand_key_type_B_192  a4 (clk, k4,         k5,  k4b);
expand_key_type_A_192  a5 (clk, k5, 8'h8,   k6,  k5b);
expand_key_type_C_192  a6 (clk, k6, 8'h10,  k7,  k6b);
expand_key_type_B_192  a7 (clk, k7,         k8,  k7b);
expand_key_type_A_192  a8 (clk, k8, 8'h20,  k9,  k8b);
expand_key_type_C_192  a9 (clk, k9, 8'h40, k10,  k9b);
expand_key_type_B_192 a10 (clk,k10,        k11, k10b);
expand_key_type_A_192 a11 (clk,k11, 8'h80,    , k11b);

one_round
    r1 (clk, s0, k0b, s1),
    r2 (clk, s1, k1b, s2),
    r3 (clk, s2, k2b, s3),
    r4 (clk, s3, k3b, s4),
    r5 (clk, s4, k4b, s5),
    r6 (clk, s5, k5b, s6),
    r7 (clk, s6, k6b, s7),
    r8 (clk, s7, k7b, s8),
    r9 (clk, s8, k8b, s9),
    r10 (clk, s9, k9b, s10),
    r11 (clk, s10, k10b, s11);

final_round
    rf (clk, s11, k11b, s12);
endmodule