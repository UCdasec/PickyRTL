module hmac (
  input  logic         clk_i,
  input  logic         rst_ni,
  input  logic         init_i,

  input  logic [255:0] key_i,
  input  logic [255:0] ikey_hash_i,
  input  logic [255:0] okey_hash_i,
  input  logic         key_hash_bypass_i,

  input  logic [511:0] message_i,

  output logic [255:0] hash_o,
  output logic         ready_o,
  output logic         hash_valid_o
);
  // Stub: no logic (keeps external IP from affecting complexity score)
endmodule
