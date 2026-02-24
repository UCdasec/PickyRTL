////////////////////////////////////////////////////////////////////////////////
// Copyright (c) 1995-2013 Xilinx, Inc.  All rights reserved.
////////////////////////////////////////////////////////////////////////////////
//   ____  ____
//  /   /\/   /
// /___/  \  /    Vendor: Xilinx
// \   \   \/     Version: P.20131013
//  \   \         Application: netgen
//  /   /         Filename: Translation_Module_DM.v
// /___/   /\     Timestamp: Fri Jul 17 11:59:08 2015
// \   \  /  \ 
//  \___\/\___\
//             
// Command	: -w -sim -ofmt verilog C:/Users/RobertHenning/Mojo_FFT_TwoDigiMics_BasicCORDIC/ipcore_dir/tmp/_cg/Translation_Module_DM.ngc C:/Users/RobertHenning/Mojo_FFT_TwoDigiMics_BasicCORDIC/ipcore_dir/tmp/_cg/Translation_Module_DM.v 
// Device	: 6slx9tqg144-2
// Input file	: C:/Users/RobertHenning/Mojo_FFT_TwoDigiMics_BasicCORDIC/ipcore_dir/tmp/_cg/Translation_Module_DM.ngc
// Output file	: C:/Users/RobertHenning/Mojo_FFT_TwoDigiMics_BasicCORDIC/ipcore_dir/tmp/_cg/Translation_Module_DM.v
// # of Modules	: 1
// Design Name	: Translation_Module_DM
// Xilinx        : C:\Xilinx\14.7\ISE_DS\ISE\
//             
// Purpose:    
//     This verilog netlist is a verification model and uses simulation 
//     primitives which may not represent the true implementation of the 
//     device, however the netlist is functionally correct and should not 
//     be modified. This file cannot be synthesized and should only be used 
//     with supported simulation tools.
//             
// Reference:  
//     Command Line Tools User Guide, Chapter 23 and Synthesis and Simulation Design Guide, Chapter 6
//             
////////////////////////////////////////////////////////////////////////////////

`timescale 1 ns/1 ps

module Translation_Module_DM (
  nd, clk, rdy, rfd, x_in, y_in, x_out, phase_out
)/* synthesis syn_black_box syn_noprune=1 */;
  input nd;
  input clk;
  output rdy;
  output rfd;
  input [9 : 0] x_in;
  input [9 : 0] y_in;
  output [9 : 0] x_out;
  output [9 : 0] phase_out;
  
  // synthesis translate_off
  
  wire \U0/i_synth/gen_cordic.output_stage/gen_rdy/gen_rtl.gen_reg.d_reg ;
  wire NlwRenamedSig_OI_rfd;
  wire sig00000001;
  wire sig00000002;
  wire sig00000003;
  wire sig00000004;
  wire sig00000005;
  wire sig00000006;
  wire sig00000007;
  wire sig00000008;
  wire sig00000009;
  wire sig0000000a;
  wire sig0000000b;
  wire sig0000000c;
  wire sig0000000d;
  wire sig0000000e;
  wire sig0000000f;
  wire sig00000010;
  wire sig00000011;
  wire sig00000012;
  wire sig00000013;
  wire sig00000014;
  wire sig00000015;
  wire sig00000016;
  wire sig00000017;
  wire sig00000018;
  wire sig00000019;
  wire sig0000001a;
  wire sig0000001b;
  wire sig0000001c;
  wire sig0000001d;
  wire sig0000001e;
  wire sig0000001f;
  wire sig00000020;
  wire sig00000021;
  wire sig00000022;
  wire sig00000023;
  wire sig00000024;
  wire sig00000025;
  wire sig00000026;
  wire sig00000027;
  wire sig00000028;
  wire sig00000029;
  wire sig0000002a;
  wire sig0000002b;
  wire sig0000002c;
  wire sig0000002d;
  wire sig0000002e;
  wire sig0000002f;
  wire sig00000030;
  wire sig00000031;
  wire sig00000032;
  wire sig00000033;
  wire sig00000034;
  wire sig00000035;
  wire sig00000036;
  wire sig00000037;
  wire sig00000038;
  wire sig00000039;
  wire sig0000003a;
  wire sig0000003b;
  wire sig0000003c;
  wire sig0000003d;
  wire sig0000003e;
  wire sig0000003f;
  wire sig00000040;
  wire sig00000041;
  wire sig00000042;
  wire sig00000043;
  wire sig00000044;
  wire sig00000045;
  wire sig00000046;
  wire sig00000047;
  wire sig00000048;
  wire sig00000049;
  wire sig0000004a;
  wire sig0000004b;
  wire sig0000004c;
  wire sig0000004d;
  wire sig0000004e;
  wire sig0000004f;
  wire sig00000050;
  wire sig00000051;
  wire sig00000052;
  wire sig00000053;
  wire sig00000054;
  wire sig00000055;
  wire sig00000056;
  wire sig00000057;
  wire sig00000058;
  wire sig00000059;
  wire sig0000005a;
  wire sig0000005b;
  wire sig0000005c;
  wire sig0000005d;
  wire sig0000005e;
  wire sig0000005f;
  wire sig00000060;
  wire sig00000061;
  wire sig00000062;
  wire sig00000063;
  wire sig00000064;
  wire sig00000065;
  wire sig00000066;
  wire sig00000067;
  wire sig00000068;
  wire sig00000069;
  wire sig0000006a;
  wire sig0000006b;
  wire sig0000006c;
  wire sig0000006d;
  wire sig0000006e;
  wire sig0000006f;
  wire sig00000070;
  wire sig00000071;
  wire sig00000072;
  wire sig00000073;
  wire sig00000074;
  wire sig00000075;
  wire sig00000076;
  wire sig00000077;
  wire sig00000078;
  wire sig00000079;
  wire sig0000007a;
  wire sig0000007b;
  wire sig0000007c;
  wire sig0000007d;
  wire sig0000007e;
  wire sig0000007f;
  wire sig00000080;
  wire sig00000081;
  wire sig00000082;
  wire sig00000083;
  wire sig00000084;
  wire sig00000085;
  wire sig00000086;
  wire sig00000087;
  wire sig00000088;
  wire sig00000089;
  wire sig0000008a;
  wire sig0000008b;
  wire sig0000008c;
  wire sig0000008d;
  wire sig0000008e;
  wire sig0000008f;
  wire sig00000090;
  wire sig00000091;
  wire sig00000092;
  wire sig00000093;
  wire sig00000094;
  wire sig00000095;
  wire sig00000096;
  wire sig00000097;
  wire sig00000098;
  wire sig00000099;
  wire sig0000009a;
  wire sig0000009b;
  wire sig0000009c;
  wire sig0000009d;
  wire sig0000009e;
  wire sig0000009f;
  wire sig000000a0;
  wire sig000000a1;
  wire sig000000a2;
  wire sig000000a3;
  wire sig000000a4;
  wire sig000000a5;
  wire sig000000a6;
  wire sig000000a7;
  wire sig000000a8;
  wire sig000000a9;
  wire sig000000aa;
  wire sig000000ab;
  wire sig000000ac;
  wire sig000000ad;
  wire sig000000ae;
  wire sig000000af;
  wire sig000000b0;
  wire sig000000b1;
  wire sig000000b2;
  wire sig000000b3;
  wire sig000000b4;
  wire sig000000b5;
  wire sig000000b6;
  wire sig000000b7;
  wire sig000000b8;
  wire sig000000b9;
  wire sig000000ba;
  wire sig000000bb;
  wire sig000000bc;
  wire sig000000bd;
  wire sig000000be;
  wire sig000000bf;
  wire sig000000c0;
  wire sig000000c1;
  wire sig000000c2;
  wire sig000000c3;
  wire sig000000c4;
  wire sig000000c5;
  wire sig000000c6;
  wire sig000000c7;
  wire sig000000c8;
  wire sig000000c9;
  wire sig000000ca;
  wire sig000000cb;
  wire sig000000cc;
  wire sig000000cd;
  wire sig000000ce;
  wire sig000000cf;
  wire sig000000d0;
  wire sig000000d1;
  wire sig000000d2;
  wire sig000000d3;
  wire sig000000d4;
  wire sig000000d5;
  wire sig000000d6;
  wire sig000000d7;
  wire sig000000d8;
  wire sig000000d9;
  wire sig000000da;
  wire sig000000db;
  wire sig000000dc;
  wire sig000000dd;
  wire sig000000de;
  wire sig000000df;
  wire sig000000e0;
  wire sig000000e1;
  wire sig000000e2;
  wire sig000000e3;
  wire sig000000e4;
  wire sig000000e5;
  wire sig000000e6;
  wire sig000000e7;
  wire sig000000e8;
  wire sig000000e9;
  wire sig000000ea;
  wire sig000000eb;
  wire sig000000ec;
  wire sig000000ed;
  wire sig000000ee;
  wire sig000000ef;
  wire sig000000f0;
  wire sig000000f1;
  wire sig000000f2;
  wire sig000000f3;
  wire sig000000f4;
  wire sig000000f5;
  wire sig000000f6;
  wire sig000000f7;
  wire sig000000f8;
  wire sig000000f9;
  wire sig000000fa;
  wire sig000000fb;
  wire sig000000fc;
  wire sig000000fd;
  wire sig000000fe;
  wire sig000000ff;
  wire sig00000100;
  wire sig00000101;
  wire sig00000102;
  wire sig00000103;
  wire sig00000104;
  wire sig00000105;
  wire sig00000106;
  wire sig00000107;
  wire sig00000108;
  wire sig00000109;
  wire sig0000010a;
  wire sig0000010b;
  wire sig0000010c;
  wire sig0000010d;
  wire sig0000010e;
  wire sig0000010f;
  wire sig00000110;
  wire sig00000111;
  wire sig00000112;
  wire sig00000113;
  wire sig00000114;
  wire sig00000115;
  wire sig00000116;
  wire sig00000117;
  wire sig00000118;
  wire sig00000119;
  wire sig0000011a;
  wire sig0000011b;
  wire sig0000011c;
  wire sig0000011d;
  wire sig0000011e;
  wire sig0000011f;
  wire sig00000120;
  wire sig00000121;
  wire sig00000122;
  wire sig00000123;
  wire sig00000124;
  wire sig00000125;
  wire sig00000126;
  wire sig00000127;
  wire sig00000128;
  wire sig00000129;
  wire sig0000012a;
  wire sig0000012b;
  wire sig0000012c;
  wire sig0000012d;
  wire sig0000012e;
  wire sig0000012f;
  wire sig00000130;
  wire sig00000131;
  wire sig00000132;
  wire sig00000133;
  wire sig00000134;
  wire sig00000135;
  wire sig00000136;
  wire sig00000137;
  wire sig00000138;
  wire sig00000139;
  wire sig0000013a;
  wire sig0000013b;
  wire sig0000013c;
  wire sig0000013d;
  wire sig0000013e;
  wire sig0000013f;
  wire sig00000140;
  wire sig00000141;
  wire sig0000014c;
  wire sig0000014d;
  wire sig0000014e;
  wire sig0000014f;
  wire sig00000150;
  wire sig00000151;
  wire sig00000152;
  wire sig00000153;
  wire sig00000154;
  wire sig00000155;
  wire sig00000156;
  wire sig00000157;
  wire sig00000158;
  wire sig00000159;
  wire sig0000015a;
  wire sig0000015b;
  wire sig0000015c;
  wire sig0000015d;
  wire sig0000015e;
  wire sig0000015f;
  wire sig00000160;
  wire sig00000161;
  wire sig00000162;
  wire sig00000163;
  wire sig00000164;
  wire sig00000165;
  wire sig00000166;
  wire sig00000167;
  wire sig00000168;
  wire sig00000169;
  wire sig0000016a;
  wire sig0000016b;
  wire sig0000016c;
  wire sig0000016d;
  wire sig0000016e;
  wire sig0000016f;
  wire sig00000170;
  wire sig00000171;
  wire sig00000172;
  wire sig00000173;
  wire sig00000174;
  wire sig00000175;
  wire sig00000176;
  wire sig00000177;
  wire sig00000178;
  wire sig00000179;
  wire sig0000017a;
  wire sig0000017b;
  wire sig0000017c;
  wire sig0000017d;
  wire sig0000017e;
  wire sig0000017f;
  wire sig00000180;
  wire sig00000181;
  wire sig00000182;
  wire sig00000183;
  wire sig00000184;
  wire sig00000185;
  wire sig00000186;
  wire sig00000187;
  wire sig00000188;
  wire sig00000189;
  wire sig0000018a;
  wire sig0000018b;
  wire sig0000018c;
  wire sig0000018d;
  wire sig0000018e;
  wire sig0000018f;
  wire sig00000190;
  wire sig00000191;
  wire sig00000192;
  wire sig00000193;
  wire sig00000194;
  wire sig00000195;
  wire sig00000196;
  wire sig00000197;
  wire sig00000198;
  wire sig00000199;
  wire sig0000019a;
  wire sig0000019b;
  wire sig0000019c;
  wire sig0000019d;
  wire sig0000019e;
  wire sig0000019f;
  wire sig000001a0;
  wire sig000001a1;
  wire sig000001a2;
  wire sig000001a3;
  wire sig000001a4;
  wire sig000001a5;
  wire sig000001a6;
  wire sig000001a7;
  wire sig000001a8;
  wire sig000001a9;
  wire sig000001aa;
  wire sig000001ab;
  wire sig000001ac;
  wire sig000001ad;
  wire sig000001ae;
  wire sig000001af;
  wire sig000001b0;
  wire sig000001b1;
  wire sig000001b2;
  wire sig000001b3;
  wire sig000001b4;
  wire sig000001b5;
  wire sig000001b6;
  wire sig000001b7;
  wire sig000001b8;
  wire sig000001b9;
  wire sig000001ba;
  wire sig000001bb;
  wire sig000001bc;
  wire sig000001bd;
  wire sig000001be;
  wire sig000001bf;
  wire sig000001c0;
  wire sig000001c1;
  wire sig000001c2;
  wire sig000001c3;
  wire sig000001c4;
  wire sig000001c5;
  wire sig000001c6;
  wire sig000001c7;
  wire sig000001c8;
  wire sig000001c9;
  wire sig000001ca;
  wire sig000001cb;
  wire sig000001cc;
  wire sig000001cd;
  wire sig000001ce;
  wire sig000001cf;
  wire sig000001d0;
  wire sig000001d1;
  wire sig000001d2;
  wire sig000001d3;
  wire sig000001d4;
  wire sig000001d5;
  wire sig000001d6;
  wire sig000001d7;
  wire sig000001d8;
  wire sig000001d9;
  wire sig000001da;
  wire sig000001db;
  wire sig000001dc;
  wire sig000001dd;
  wire sig000001de;
  wire sig000001df;
  wire sig000001e0;
  wire sig000001e1;
  wire sig000001e2;
  wire sig000001e3;
  wire sig000001e4;
  wire sig000001e5;
  wire sig000001e6;
  wire sig000001e7;
  wire sig000001e8;
  wire sig000001e9;
  wire sig000001ea;
  wire sig000001eb;
  wire sig000001ec;
  wire sig000001ed;
  wire sig000001ee;
  wire sig000001ef;
  wire sig000001f0;
  wire sig000001f1;
  wire sig000001f2;
  wire sig000001f3;
  wire sig000001f4;
  wire sig000001f5;
  wire sig000001f6;
  wire sig000001f7;
  wire sig000001f8;
  wire sig000001f9;
  wire sig000001fa;
  wire sig000001fb;
  wire sig000001fc;
  wire sig000001fd;
  wire sig000001fe;
  wire sig000001ff;
  wire sig00000200;
  wire sig00000201;
  wire sig00000202;
  wire sig00000203;
  wire sig00000204;
  wire sig00000205;
  wire sig00000206;
  wire \blk0000001a/sig0000023d ;
  wire \blk0000001a/sig0000023c ;
  wire \blk0000001a/sig0000023b ;
  wire \blk0000001a/sig0000023a ;
  wire \blk0000001a/sig00000239 ;
  wire \blk0000001a/sig00000238 ;
  wire \blk0000001a/sig00000237 ;
  wire \blk0000001a/sig00000236 ;
  wire \blk0000001a/sig00000235 ;
  wire \blk0000001a/sig00000234 ;
  wire \blk0000001a/sig00000233 ;
  wire \blk0000001a/sig00000232 ;
  wire \blk0000001a/sig00000231 ;
  wire \blk0000001a/sig00000230 ;
  wire \blk0000001a/sig0000022f ;
  wire \blk0000001a/sig0000022e ;
  wire \blk0000001a/sig0000022d ;
  wire \blk0000001a/sig0000022c ;
  wire \blk0000001a/sig0000022b ;
  wire \blk0000001a/sig0000022a ;
  wire \blk0000001a/sig00000229 ;
  wire \blk0000001a/sig00000228 ;
  wire \blk0000001a/sig00000227 ;
  wire \blk0000001a/sig00000226 ;
  wire \blk0000001a/sig00000225 ;
  wire \blk0000001a/sig00000224 ;
  wire \blk0000001a/sig00000223 ;
  wire \blk0000001a/sig00000222 ;
  wire \blk00000046/sig00000274 ;
  wire \blk00000046/sig00000273 ;
  wire \blk00000046/sig00000272 ;
  wire \blk00000046/sig00000271 ;
  wire \blk00000046/sig00000270 ;
  wire \blk00000046/sig0000026f ;
  wire \blk00000046/sig0000026e ;
  wire \blk00000046/sig0000026d ;
  wire \blk00000046/sig0000026c ;
  wire \blk00000046/sig0000026b ;
  wire \blk00000046/sig0000026a ;
  wire \blk00000046/sig00000269 ;
  wire \blk00000046/sig00000268 ;
  wire \blk00000046/sig00000267 ;
  wire \blk00000046/sig00000266 ;
  wire \blk00000046/sig00000265 ;
  wire \blk00000046/sig00000264 ;
  wire \blk00000046/sig00000263 ;
  wire \blk00000046/sig00000262 ;
  wire \blk00000046/sig00000261 ;
  wire \blk00000046/sig00000260 ;
  wire \blk00000046/sig0000025f ;
  wire \blk00000046/sig0000025e ;
  wire \blk00000046/sig0000025d ;
  wire \blk00000046/sig0000025c ;
  wire \blk00000046/sig0000025b ;
  wire \blk00000046/sig0000025a ;
  wire \blk00000046/sig00000259 ;
  wire \blk00000086/sig000002c1 ;
  wire \blk00000086/sig000002c0 ;
  wire \blk00000086/sig000002bf ;
  wire \blk00000086/sig000002be ;
  wire \blk00000086/sig000002bd ;
  wire \blk00000086/sig000002bc ;
  wire \blk00000086/sig000002bb ;
  wire \blk00000086/sig000002ba ;
  wire \blk00000086/sig000002b9 ;
  wire \blk00000086/sig000002b8 ;
  wire \blk00000086/sig000002b7 ;
  wire \blk00000086/sig000002b6 ;
  wire \blk00000086/sig000002b5 ;
  wire \blk00000086/sig000002b4 ;
  wire \blk00000086/sig000002b3 ;
  wire \blk00000086/sig000002b2 ;
  wire \blk00000086/sig000002b1 ;
  wire \blk00000086/sig000002b0 ;
  wire \blk00000086/sig000002af ;
  wire \blk00000086/sig000002ae ;
  wire \blk00000086/sig000002ad ;
  wire \blk00000086/sig000002ac ;
  wire \blk00000086/sig000002ab ;
  wire \blk00000086/sig000002aa ;
  wire \blk00000086/sig000002a9 ;
  wire \blk00000086/sig000002a8 ;
  wire \blk00000086/sig000002a7 ;
  wire \blk00000086/sig000002a6 ;
  wire \blk00000086/sig000002a5 ;
  wire \blk00000086/sig000002a4 ;
  wire \blk00000086/sig000002a3 ;
  wire \blk00000086/sig000002a2 ;
  wire \blk00000086/sig000002a1 ;
  wire \blk00000086/sig000002a0 ;
  wire \blk00000086/sig0000029f ;
  wire \blk00000086/sig0000029e ;
  wire \blk00000086/sig0000029d ;
  wire \blk00000086/sig0000029c ;
  wire \blk00000086/sig0000029b ;
  wire \blk00000086/sig0000029a ;
  wire \blk000000bd/sig0000030e ;
  wire \blk000000bd/sig0000030d ;
  wire \blk000000bd/sig0000030c ;
  wire \blk000000bd/sig0000030b ;
  wire \blk000000bd/sig0000030a ;
  wire \blk000000bd/sig00000309 ;
  wire \blk000000bd/sig00000308 ;
  wire \blk000000bd/sig00000307 ;
  wire \blk000000bd/sig00000306 ;
  wire \blk000000bd/sig00000305 ;
  wire \blk000000bd/sig00000304 ;
  wire \blk000000bd/sig00000303 ;
  wire \blk000000bd/sig00000302 ;
  wire \blk000000bd/sig00000301 ;
  wire \blk000000bd/sig00000300 ;
  wire \blk000000bd/sig000002ff ;
  wire \blk000000bd/sig000002fe ;
  wire \blk000000bd/sig000002fd ;
  wire \blk000000bd/sig000002fc ;
  wire \blk000000bd/sig000002fb ;
  wire \blk000000bd/sig000002fa ;
  wire \blk000000bd/sig000002f9 ;
  wire \blk000000bd/sig000002f8 ;
  wire \blk000000bd/sig000002f7 ;
  wire \blk000000bd/sig000002f6 ;
  wire \blk000000bd/sig000002f5 ;
  wire \blk000000bd/sig000002f4 ;
  wire \blk000000bd/sig000002f3 ;
  wire \blk000000bd/sig000002f2 ;
  wire \blk000000bd/sig000002f1 ;
  wire \blk000000bd/sig000002f0 ;
  wire \blk000000bd/sig000002ef ;
  wire \blk000000bd/sig000002ee ;
  wire \blk000000bd/sig000002ed ;
  wire \blk000000bd/sig000002ec ;
  wire \blk000000bd/sig000002eb ;
  wire \blk000000bd/sig000002ea ;
  wire \blk000000bd/sig000002e9 ;
  wire \blk000000bd/sig000002e8 ;
  wire \blk000000bd/sig000002e7 ;
  wire \blk000000f4/sig0000035b ;
  wire \blk000000f4/sig0000035a ;
  wire \blk000000f4/sig00000359 ;
  wire \blk000000f4/sig00000358 ;
  wire \blk000000f4/sig00000357 ;
  wire \blk000000f4/sig00000356 ;
  wire \blk000000f4/sig00000355 ;
  wire \blk000000f4/sig00000354 ;
  wire \blk000000f4/sig00000353 ;
  wire \blk000000f4/sig00000352 ;
  wire \blk000000f4/sig00000351 ;
  wire \blk000000f4/sig00000350 ;
  wire \blk000000f4/sig0000034f ;
  wire \blk000000f4/sig0000034e ;
  wire \blk000000f4/sig0000034d ;
  wire \blk000000f4/sig0000034c ;
  wire \blk000000f4/sig0000034b ;
  wire \blk000000f4/sig0000034a ;
  wire \blk000000f4/sig00000349 ;
  wire \blk000000f4/sig00000348 ;
  wire \blk000000f4/sig00000347 ;
  wire \blk000000f4/sig00000346 ;
  wire \blk000000f4/sig00000345 ;
  wire \blk000000f4/sig00000344 ;
  wire \blk000000f4/sig00000343 ;
  wire \blk000000f4/sig00000342 ;
  wire \blk000000f4/sig00000341 ;
  wire \blk000000f4/sig00000340 ;
  wire \blk000000f4/sig0000033f ;
  wire \blk000000f4/sig0000033e ;
  wire \blk000000f4/sig0000033d ;
  wire \blk000000f4/sig0000033c ;
  wire \blk000000f4/sig0000033b ;
  wire \blk000000f4/sig0000033a ;
  wire \blk000000f4/sig00000339 ;
  wire \blk000000f4/sig00000338 ;
  wire \blk000000f4/sig00000337 ;
  wire \blk000000f4/sig00000336 ;
  wire \blk000000f4/sig00000335 ;
  wire \blk000000f4/sig00000334 ;
  wire \blk000000f4/sig00000333 ;
  wire \blk0000012c/sig000003ad ;
  wire \blk0000012c/sig000003ac ;
  wire \blk0000012c/sig000003ab ;
  wire \blk0000012c/sig000003aa ;
  wire \blk0000012c/sig000003a9 ;
  wire \blk0000012c/sig000003a8 ;
  wire \blk0000012c/sig000003a7 ;
  wire \blk0000012c/sig000003a6 ;
  wire \blk0000012c/sig000003a5 ;
  wire \blk0000012c/sig000003a4 ;
  wire \blk0000012c/sig000003a3 ;
  wire \blk0000012c/sig000003a2 ;
  wire \blk0000012c/sig000003a1 ;
  wire \blk0000012c/sig000003a0 ;
  wire \blk0000012c/sig0000039f ;
  wire \blk0000012c/sig0000039e ;
  wire \blk0000012c/sig0000039d ;
  wire \blk0000012c/sig0000039c ;
  wire \blk0000012c/sig0000039b ;
  wire \blk0000012c/sig0000039a ;
  wire \blk0000012c/sig00000399 ;
  wire \blk0000012c/sig00000398 ;
  wire \blk0000012c/sig00000397 ;
  wire \blk0000012c/sig00000396 ;
  wire \blk0000012c/sig00000395 ;
  wire \blk0000012c/sig00000394 ;
  wire \blk0000012c/sig00000393 ;
  wire \blk0000012c/sig00000392 ;
  wire \blk0000012c/sig00000391 ;
  wire \blk0000012c/sig00000390 ;
  wire \blk0000012c/sig0000038f ;
  wire \blk0000012c/sig0000038e ;
  wire \blk0000012c/sig0000038d ;
  wire \blk0000012c/sig0000038c ;
  wire \blk0000012c/sig0000038b ;
  wire \blk0000012c/sig0000038a ;
  wire \blk0000012c/sig00000389 ;
  wire \blk0000012c/sig00000388 ;
  wire \blk0000012c/sig00000387 ;
  wire \blk0000012c/sig00000386 ;
  wire \blk0000012c/sig00000385 ;
  wire \blk00000164/sig000003ff ;
  wire \blk00000164/sig000003fe ;
  wire \blk00000164/sig000003fd ;
  wire \blk00000164/sig000003fc ;
  wire \blk00000164/sig000003fb ;
  wire \blk00000164/sig000003fa ;
  wire \blk00000164/sig000003f9 ;
  wire \blk00000164/sig000003f8 ;
  wire \blk00000164/sig000003f7 ;
  wire \blk00000164/sig000003f6 ;
  wire \blk00000164/sig000003f5 ;
  wire \blk00000164/sig000003f4 ;
  wire \blk00000164/sig000003f3 ;
  wire \blk00000164/sig000003f2 ;
  wire \blk00000164/sig000003f1 ;
  wire \blk00000164/sig000003f0 ;
  wire \blk00000164/sig000003ef ;
  wire \blk00000164/sig000003ee ;
  wire \blk00000164/sig000003ed ;
  wire \blk00000164/sig000003ec ;
  wire \blk00000164/sig000003eb ;
  wire \blk00000164/sig000003ea ;
  wire \blk00000164/sig000003e9 ;
  wire \blk00000164/sig000003e8 ;
  wire \blk00000164/sig000003e7 ;
  wire \blk00000164/sig000003e6 ;
  wire \blk00000164/sig000003e5 ;
  wire \blk00000164/sig000003e4 ;
  wire \blk00000164/sig000003e3 ;
  wire \blk00000164/sig000003e2 ;
  wire \blk00000164/sig000003e1 ;
  wire \blk00000164/sig000003e0 ;
  wire \blk00000164/sig000003df ;
  wire \blk00000164/sig000003de ;
  wire \blk00000164/sig000003dd ;
  wire \blk00000164/sig000003dc ;
  wire \blk00000164/sig000003db ;
  wire \blk00000164/sig000003da ;
  wire \blk00000164/sig000003d9 ;
  wire \blk00000164/sig000003d8 ;
  wire \blk00000164/sig000003d7 ;
  wire \blk000001b7/sig00000417 ;
  wire \blk000001b7/sig00000416 ;
  wire \blk000001b7/sig00000415 ;
  wire \blk000001b7/sig00000414 ;
  wire \blk000001b7/sig00000413 ;
  wire \blk000001b7/sig00000412 ;
  wire \blk000001b7/sig00000411 ;
  wire \blk000001b7/sig00000410 ;
  wire \blk000001b7/sig0000040f ;
  wire \blk000001b7/sig0000040e ;
  wire \blk000001b7/sig0000040d ;
  wire \blk000001b7/sig0000040c ;
  wire \blk000001b7/sig0000040b ;
  wire \blk000001ca/sig0000042f ;
  wire \blk000001ca/sig0000042e ;
  wire \blk000001ca/sig0000042d ;
  wire \blk000001ca/sig0000042c ;
  wire \blk000001ca/sig0000042b ;
  wire \blk000001ca/sig0000042a ;
  wire \blk000001ca/sig00000429 ;
  wire \blk000001ca/sig00000428 ;
  wire \blk000001ca/sig00000427 ;
  wire \blk000001ca/sig00000426 ;
  wire \blk000001ca/sig00000425 ;
  wire \blk000001ca/sig00000424 ;
  wire \blk000001ca/sig00000423 ;
  wire \blk000001e5/sig00000472 ;
  wire \blk000001e5/sig00000471 ;
  wire \blk000001e5/sig00000470 ;
  wire \blk000001e5/sig0000046f ;
  wire \blk000001e5/sig0000046e ;
  wire \blk000001e5/sig0000046d ;
  wire \blk000001e5/sig0000046c ;
  wire \blk000001e5/sig0000046b ;
  wire \blk000001e5/sig0000046a ;
  wire \blk000001e5/sig00000469 ;
  wire \blk000001e5/sig00000468 ;
  wire \blk000001e5/sig00000467 ;
  wire \blk000001e5/sig00000466 ;
  wire \blk000001e5/sig00000465 ;
  wire \blk000001e5/sig00000464 ;
  wire \blk000001e5/sig00000463 ;
  wire \blk000001e5/sig00000462 ;
  wire \blk000001e5/sig00000461 ;
  wire \blk000001e5/sig00000460 ;
  wire \blk000001e5/sig0000045f ;
  wire \blk000001e5/sig0000045e ;
  wire \blk000001e5/sig0000045d ;
  wire \blk000001e5/sig0000045c ;
  wire \blk000001e5/sig0000045b ;
  wire \blk000001e5/sig0000045a ;
  wire \blk000001e5/sig00000459 ;
  wire \blk000001e5/sig00000458 ;
  wire \blk000001e5/sig00000457 ;
  wire \blk000001e5/sig00000456 ;
  wire \blk000001e5/sig00000455 ;
  wire \blk000001e5/sig00000454 ;
  wire \blk000001e5/sig00000453 ;
  wire \blk000001e5/sig00000452 ;
  wire \blk000001e5/sig00000451 ;
  wire \blk000001e5/sig00000450 ;
  wire \blk000001e5/sig0000044f ;
  wire \blk000001e5/sig0000044e ;
  wire \blk000001e5/sig0000044d ;
  wire \blk000002d2/sig000004a5 ;
  wire \blk000002d2/sig000004a4 ;
  wire \blk000002d2/sig000004a3 ;
  wire \blk000002d2/sig000004a2 ;
  wire \blk000002d2/sig000004a1 ;
  wire \blk000002d2/sig000004a0 ;
  wire \blk000002d2/sig0000049f ;
  wire \blk000002d2/sig0000049e ;
  wire \blk000002d2/sig0000049d ;
  wire \blk000002d2/sig0000049c ;
  wire \blk000002d2/sig0000049b ;
  wire \blk000002d2/sig0000049a ;
  wire \blk000002d2/sig00000499 ;
  wire \blk000002d2/sig00000498 ;
  wire NLW_blk000001ab_LO_UNCONNECTED;
  wire NLW_blk00000363_Q15_UNCONNECTED;
  wire NLW_blk00000365_Q15_UNCONNECTED;
  wire NLW_blk00000367_Q15_UNCONNECTED;
  wire NLW_blk00000369_Q15_UNCONNECTED;
  wire NLW_blk0000036b_Q15_UNCONNECTED;
  wire NLW_blk0000036d_Q15_UNCONNECTED;
  wire NLW_blk0000036f_Q15_UNCONNECTED;
  wire NLW_blk00000371_Q15_UNCONNECTED;
  wire NLW_blk00000373_Q15_UNCONNECTED;
  wire NLW_blk00000375_Q15_UNCONNECTED;
  wire NLW_blk00000377_Q15_UNCONNECTED;
  wire NLW_blk00000379_Q15_UNCONNECTED;
  wire NLW_blk0000037b_Q15_UNCONNECTED;
  wire NLW_blk0000037c_Q15_UNCONNECTED;
  wire NLW_blk0000037e_Q15_UNCONNECTED;
  wire NLW_blk00000380_Q15_UNCONNECTED;
  wire NLW_blk00000381_Q15_UNCONNECTED;
  wire NLW_blk00000382_Q15_UNCONNECTED;
  wire NLW_blk00000383_Q15_UNCONNECTED;
  wire NLW_blk00000384_Q15_UNCONNECTED;
  wire NLW_blk00000385_Q15_UNCONNECTED;
  wire NLW_blk00000386_Q15_UNCONNECTED;
  wire NLW_blk00000387_Q15_UNCONNECTED;
  wire NLW_blk00000388_Q15_UNCONNECTED;
  wire NLW_blk00000389_Q15_UNCONNECTED;
  wire \NLW_blk0000001a/blk0000002a_O_UNCONNECTED ;
  wire \NLW_blk0000001a/blk00000029_O_UNCONNECTED ;
  wire \NLW_blk0000001a/blk00000028_O_UNCONNECTED ;
  wire \NLW_blk0000001a/blk00000027_O_UNCONNECTED ;
  wire \NLW_blk0000001a/blk00000026_O_UNCONNECTED ;
  wire \NLW_blk0000001a/blk00000025_O_UNCONNECTED ;
  wire \NLW_blk0000001a/blk00000024_O_UNCONNECTED ;
  wire \NLW_blk0000001a/blk00000023_O_UNCONNECTED ;
  wire \NLW_blk0000001a/blk00000022_O_UNCONNECTED ;
  wire \NLW_blk0000001a/blk00000021_O_UNCONNECTED ;
  wire \NLW_blk0000001a/blk00000020_O_UNCONNECTED ;
  wire \NLW_blk0000001a/blk0000001f_O_UNCONNECTED ;
  wire \NLW_blk0000001a/blk0000001d_O_UNCONNECTED ;
  wire \NLW_blk0000001a/blk0000001c_O_UNCONNECTED ;
  wire \NLW_blk00000046/blk00000057_O_UNCONNECTED ;
  wire \NLW_blk00000046/blk00000056_O_UNCONNECTED ;
  wire \NLW_blk00000046/blk00000055_O_UNCONNECTED ;
  wire \NLW_blk00000046/blk00000054_O_UNCONNECTED ;
  wire \NLW_blk00000046/blk00000053_O_UNCONNECTED ;
  wire \NLW_blk00000046/blk00000052_O_UNCONNECTED ;
  wire \NLW_blk00000046/blk00000051_O_UNCONNECTED ;
  wire \NLW_blk00000046/blk00000050_O_UNCONNECTED ;
  wire \NLW_blk00000046/blk0000004f_O_UNCONNECTED ;
  wire \NLW_blk00000046/blk0000004e_O_UNCONNECTED ;
  wire \NLW_blk00000046/blk0000004d_O_UNCONNECTED ;
  wire \NLW_blk00000046/blk0000004c_O_UNCONNECTED ;
  wire \NLW_blk00000046/blk0000004a_O_UNCONNECTED ;
  wire \NLW_blk00000046/blk00000049_O_UNCONNECTED ;
  wire \NLW_blk00000086/blk00000094_O_UNCONNECTED ;
  wire \NLW_blk00000086/blk00000087_O_UNCONNECTED ;
  wire \NLW_blk000000bd/blk000000cb_O_UNCONNECTED ;
  wire \NLW_blk000000bd/blk000000be_O_UNCONNECTED ;
  wire \NLW_blk000000f4/blk000000f5_O_UNCONNECTED ;
  wire \NLW_blk0000012c/blk0000012d_O_UNCONNECTED ;
  wire \NLW_blk00000164/blk00000165_O_UNCONNECTED ;
  wire \NLW_blk000001b7/blk000001ba_O_UNCONNECTED ;
  wire \NLW_blk000001ca/blk000001cd_O_UNCONNECTED ;
  wire \NLW_blk000001e5/blk000001f3_O_UNCONNECTED ;
  wire \NLW_blk000001e5/blk000001f2_O_UNCONNECTED ;
  wire \NLW_blk000001e5/blk000001f1_O_UNCONNECTED ;
  wire \NLW_blk000001e5/blk000001e6_O_UNCONNECTED ;
  wire [9 : 0] \U0/i_synth/gen_cordic.output_stage/gen_x_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg ;
  wire [9 : 0] \U0/i_synth/gen_cordic.output_stage/gen_phase_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg ;
  assign
    x_out[9] = \U0/i_synth/gen_cordic.output_stage/gen_x_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [9],
    x_out[8] = \U0/i_synth/gen_cordic.output_stage/gen_x_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [8],
    x_out[7] = \U0/i_synth/gen_cordic.output_stage/gen_x_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [7],
    x_out[6] = \U0/i_synth/gen_cordic.output_stage/gen_x_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [6],
    x_out[5] = \U0/i_synth/gen_cordic.output_stage/gen_x_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [5],
    x_out[4] = \U0/i_synth/gen_cordic.output_stage/gen_x_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [4],
    x_out[3] = \U0/i_synth/gen_cordic.output_stage/gen_x_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [3],
    x_out[2] = \U0/i_synth/gen_cordic.output_stage/gen_x_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [2],
    x_out[1] = \U0/i_synth/gen_cordic.output_stage/gen_x_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [1],
    x_out[0] = \U0/i_synth/gen_cordic.output_stage/gen_x_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [0],
    phase_out[9] = \U0/i_synth/gen_cordic.output_stage/gen_phase_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [9],
    phase_out[8] = \U0/i_synth/gen_cordic.output_stage/gen_phase_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [8],
    phase_out[7] = \U0/i_synth/gen_cordic.output_stage/gen_phase_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [7],
    phase_out[6] = \U0/i_synth/gen_cordic.output_stage/gen_phase_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [6],
    phase_out[5] = \U0/i_synth/gen_cordic.output_stage/gen_phase_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [5],
    phase_out[4] = \U0/i_synth/gen_cordic.output_stage/gen_phase_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [4],
    phase_out[3] = \U0/i_synth/gen_cordic.output_stage/gen_phase_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [3],
    phase_out[2] = \U0/i_synth/gen_cordic.output_stage/gen_phase_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [2],
    phase_out[1] = \U0/i_synth/gen_cordic.output_stage/gen_phase_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [1],
    phase_out[0] = \U0/i_synth/gen_cordic.output_stage/gen_phase_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [0],
    rdy = \U0/i_synth/gen_cordic.output_stage/gen_rdy/gen_rtl.gen_reg.d_reg ,
    rfd = NlwRenamedSig_OI_rfd;
  VCC   blk00000001 (
    .P(sig00000001)
  );
  GND   blk00000002 (
    .G(sig000000a0)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000003 (
    .C(clk),
    .D(sig00000095),
    .Q(sig0000002d)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000004 (
    .C(clk),
    .D(sig00000094),
    .Q(sig0000002e)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000005 (
    .C(clk),
    .D(nd),
    .Q(sig0000002c)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000006 (
    .C(clk),
    .D(y_in[9]),
    .Q(sig000000ca)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000007 (
    .C(clk),
    .D(y_in[8]),
    .Q(sig000000c9)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000008 (
    .C(clk),
    .D(y_in[7]),
    .Q(sig000000c8)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000009 (
    .C(clk),
    .D(y_in[6]),
    .Q(sig000000c7)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk0000000a (
    .C(clk),
    .D(y_in[5]),
    .Q(sig000000c6)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk0000000b (
    .C(clk),
    .D(y_in[4]),
    .Q(sig000000c5)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk0000000c (
    .C(clk),
    .D(y_in[3]),
    .Q(sig000000c4)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk0000000d (
    .C(clk),
    .D(y_in[2]),
    .Q(sig000000c3)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk0000000e (
    .C(clk),
    .D(y_in[1]),
    .Q(sig000000c2)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk0000000f (
    .C(clk),
    .D(y_in[0]),
    .Q(sig000000c1)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000010 (
    .C(clk),
    .D(x_in[9]),
    .Q(sig000000d4)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000011 (
    .C(clk),
    .D(x_in[8]),
    .Q(sig000000d3)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000012 (
    .C(clk),
    .D(x_in[7]),
    .Q(sig000000d2)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000013 (
    .C(clk),
    .D(x_in[6]),
    .Q(sig000000d1)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000014 (
    .C(clk),
    .D(x_in[5]),
    .Q(sig000000d0)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000015 (
    .C(clk),
    .D(x_in[4]),
    .Q(sig000000cf)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000016 (
    .C(clk),
    .D(x_in[3]),
    .Q(sig000000ce)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000017 (
    .C(clk),
    .D(x_in[2]),
    .Q(sig000000cd)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000018 (
    .C(clk),
    .D(x_in[1]),
    .Q(sig000000cc)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000019 (
    .C(clk),
    .D(x_in[0]),
    .Q(sig000000cb)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000072 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000ca),
    .R(sig000000a0),
    .Q(sig000000b4)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000073 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000c9),
    .R(sig000000a0),
    .Q(sig000000b3)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000074 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000c8),
    .R(sig000000a0),
    .Q(sig000000b2)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000075 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000c7),
    .R(sig000000a0),
    .Q(sig000000b1)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000076 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000c6),
    .R(sig000000a0),
    .Q(sig000000b0)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000077 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000c5),
    .R(sig000000a0),
    .Q(sig000000af)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000078 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000c4),
    .R(sig000000a0),
    .Q(sig000000ae)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000079 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000c3),
    .R(sig000000a0),
    .Q(sig000000ad)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000007a (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000c2),
    .R(sig000000a0),
    .Q(sig000000ac)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000007b (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000c1),
    .R(sig000000a0),
    .Q(sig000000ab)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000007c (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000d4),
    .R(sig000000a0),
    .Q(sig000000be)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000007d (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000d3),
    .R(sig000000a0),
    .Q(sig000000bd)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000007e (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000d2),
    .R(sig000000a0),
    .Q(sig000000bc)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000007f (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000d1),
    .R(sig000000a0),
    .Q(sig000000bb)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000080 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000d0),
    .R(sig000000a0),
    .Q(sig000000ba)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000081 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000cf),
    .R(sig000000a0),
    .Q(sig000000b9)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000082 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000ce),
    .R(sig000000a0),
    .Q(sig000000b8)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000083 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000cd),
    .R(sig000000a0),
    .Q(sig000000b7)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000084 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000cc),
    .R(sig000000a0),
    .Q(sig000000b6)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000085 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000cb),
    .R(sig000000a0),
    .Q(sig000000b5)
  );
  LUT6 #(
    .INIT ( 64'hFDECB9A875643120 ))
  blk0000019c (
    .I0(sig00000052),
    .I1(sig00000053),
    .I2(sig00000077),
    .I3(sig00000076),
    .I4(sig00000078),
    .I5(sig00000079),
    .O(sig000000d5)
  );
  LUT6 #(
    .INIT ( 64'hFEDC7654BA983210 ))
  blk0000019d (
    .I0(sig00000052),
    .I1(sig00000053),
    .I2(sig00000072),
    .I3(sig00000073),
    .I4(sig00000075),
    .I5(sig00000074),
    .O(sig000000d6)
  );
  MUXF7   blk0000019e (
    .I0(sig000000d6),
    .I1(sig000000d5),
    .S(sig00000054),
    .O(sig0000005b)
  );
  LUT6 #(
    .INIT ( 64'hFD75B931EC64A820 ))
  blk0000019f (
    .I0(sig00000053),
    .I1(sig00000052),
    .I2(sig00000077),
    .I3(sig00000078),
    .I4(sig00000076),
    .I5(sig00000075),
    .O(sig000000d7)
  );
  LUT6 #(
    .INIT ( 64'hFEDCBA9876543210 ))
  blk000001a0 (
    .I0(sig00000052),
    .I1(sig00000053),
    .I2(sig00000071),
    .I3(sig00000072),
    .I4(sig00000073),
    .I5(sig00000074),
    .O(sig000000d8)
  );
  MUXF7   blk000001a1 (
    .I0(sig000000d8),
    .I1(sig000000d7),
    .S(sig00000054),
    .O(sig0000005a)
  );
  LUT6 #(
    .INIT ( 64'hF7E6D5C4B3A29180 ))
  blk000001a2 (
    .I0(sig00000052),
    .I1(sig00000053),
    .I2(sig00000082),
    .I3(sig0000007f),
    .I4(sig00000080),
    .I5(sig00000081),
    .O(sig000000d9)
  );
  LUT6 #(
    .INIT ( 64'hFD75EC64B931A820 ))
  blk000001a3 (
    .I0(sig00000052),
    .I1(sig00000053),
    .I2(sig00000083),
    .I3(sig00000085),
    .I4(sig00000082),
    .I5(sig00000084),
    .O(sig000000da)
  );
  LUT6 #(
    .INIT ( 64'hFEDC7654BA983210 ))
  blk000001a4 (
    .I0(sig00000052),
    .I1(sig00000053),
    .I2(sig0000007e),
    .I3(sig0000007f),
    .I4(sig00000081),
    .I5(sig00000080),
    .O(sig000000db)
  );
  MUXF7   blk000001a5 (
    .I0(sig000000db),
    .I1(sig000000da),
    .S(sig00000054),
    .O(sig00000066)
  );
  LUT6 #(
    .INIT ( 64'hFD75B931EC64A820 ))
  blk000001a6 (
    .I0(sig00000053),
    .I1(sig00000052),
    .I2(sig00000083),
    .I3(sig00000084),
    .I4(sig00000082),
    .I5(sig00000081),
    .O(sig000000dc)
  );
  LUT6 #(
    .INIT ( 64'hFEDCBA9876543210 ))
  blk000001a7 (
    .I0(sig00000052),
    .I1(sig00000053),
    .I2(sig0000007d),
    .I3(sig0000007e),
    .I4(sig0000007f),
    .I5(sig00000080),
    .O(sig000000dd)
  );
  MUXF7   blk000001a8 (
    .I0(sig000000dd),
    .I1(sig000000dc),
    .S(sig00000054),
    .O(sig00000065)
  );
  LUT6 #(
    .INIT ( 64'hFEDCBA9876543210 ))
  blk000001a9 (
    .I0(sig00000052),
    .I1(sig00000053),
    .I2(sig00000083),
    .I3(sig00000084),
    .I4(sig00000085),
    .I5(sig00000086),
    .O(sig000000de)
  );
  MUXF7   blk000001aa (
    .I0(sig000000d9),
    .I1(sig000000de),
    .S(sig00000054),
    .O(sig00000067)
  );
  MUXCY_D   blk000001ab (
    .CI(sig00000001),
    .DI(sig000000a0),
    .S(sig000000df),
    .O(sig000000e0),
    .LO(NLW_blk000001ab_LO_UNCONNECTED)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk000001ac (
    .C(clk),
    .CE(sig0000004f),
    .D(sig0000002d),
    .Q(sig00000003)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk000001ad (
    .C(clk),
    .CE(sig0000004f),
    .D(sig0000002e),
    .Q(sig00000004)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000001ae (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000e0),
    .R(sig000000a0),
    .Q(sig000000ea)
  );
  FDS #(
    .INIT ( 1'b1 ))
  blk000001af (
    .C(clk),
    .D(sig00000055),
    .S(sig000000e9),
    .Q(sig00000052)
  );
  FDS #(
    .INIT ( 1'b1 ))
  blk000001b0 (
    .C(clk),
    .D(sig00000056),
    .S(sig000000e9),
    .Q(sig00000053)
  );
  FDS #(
    .INIT ( 1'b1 ))
  blk000001b1 (
    .C(clk),
    .D(sig00000057),
    .S(sig000000e9),
    .Q(sig00000054)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000001b2 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000e6),
    .R(sig000000a0),
    .Q(sig000000e7)
  );
  FD #(
    .INIT ( 1'b1 ))
  blk000001b3 (
    .C(clk),
    .D(NlwRenamedSig_OI_rfd),
    .Q(sig000000eb)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk000001b4 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000e9),
    .Q(sig000000e8)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk000001b5 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000e8),
    .Q(sig0000004f)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000001b6 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000ea),
    .R(sig000000a0),
    .Q(sig00000002)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk000001dd (
    .C(clk),
    .D(sig000000ec),
    .Q(sig0000004e)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk000001de (
    .C(clk),
    .D(sig000000ed),
    .Q(sig0000004d)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk000001df (
    .C(clk),
    .D(sig000000ee),
    .Q(sig0000004c)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk000001e0 (
    .C(clk),
    .D(sig000000ef),
    .Q(sig0000004b)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk000001e1 (
    .C(clk),
    .D(sig000000f0),
    .Q(sig0000004a)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk000001e2 (
    .C(clk),
    .D(sig000000f1),
    .Q(sig00000049)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk000001e3 (
    .C(clk),
    .D(sig000000f2),
    .Q(sig00000048)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk000001e4 (
    .C(clk),
    .D(sig000000f3),
    .Q(sig00000047)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000021a (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000005),
    .R(sig000000a0),
    .Q(sig0000015a)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000021b (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000006),
    .R(sig000000a0),
    .Q(sig0000015b)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000021c (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000007),
    .R(sig000000a0),
    .Q(sig0000015c)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000021d (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000008),
    .R(sig000000a0),
    .Q(sig0000015d)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000021e (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000009),
    .R(sig000000a0),
    .Q(sig0000015e)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000021f (
    .C(clk),
    .CE(sig00000001),
    .D(sig0000000a),
    .R(sig000000a0),
    .Q(sig0000015f)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000220 (
    .C(clk),
    .CE(sig00000001),
    .D(sig0000000b),
    .R(sig000000a0),
    .Q(sig00000160)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000221 (
    .C(clk),
    .CE(sig00000001),
    .D(sig0000000c),
    .R(sig000000a0),
    .Q(sig00000161)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000222 (
    .C(clk),
    .CE(sig00000001),
    .D(sig0000000d),
    .R(sig000000a0),
    .Q(sig00000162)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000223 (
    .C(clk),
    .CE(sig00000001),
    .D(sig0000000e),
    .R(sig000000a0),
    .Q(sig00000163)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000224 (
    .C(clk),
    .CE(sig00000001),
    .D(sig0000000f),
    .R(sig000000a0),
    .Q(sig00000164)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000225 (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000010),
    .R(sig000000a0),
    .Q(sig00000165)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000226 (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000011),
    .R(sig000000a0),
    .Q(sig00000166)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000227 (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000135),
    .R(sig000000a0),
    .Q(sig00000158)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000228 (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000134),
    .R(sig000000a0),
    .Q(sig00000159)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000229 (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000136),
    .R(sig000000a0),
    .Q(sig0000014d)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000022a (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000137),
    .R(sig000000a0),
    .Q(\U0/i_synth/gen_cordic.output_stage/gen_rdy/gen_rtl.gen_reg.d_reg )
  );
  RAM64X1S #(
    .INIT ( 64'hFFFFFFC000000000 ))
  blk0000022b (
    .A0(sig00000167),
    .A1(sig00000168),
    .A2(sig00000169),
    .A3(sig0000016a),
    .A4(sig0000016b),
    .A5(sig0000016c),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig0000017e)
  );
  RAM64X1S #(
    .INIT ( 64'hFF00003FFFF80000 ))
  blk0000022c (
    .A0(sig00000167),
    .A1(sig00000168),
    .A2(sig00000169),
    .A3(sig0000016a),
    .A4(sig0000016b),
    .A5(sig0000016c),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig0000017d)
  );
  RAM64X1S #(
    .INIT ( 64'h00FF803FF007FC00 ))
  blk0000022d (
    .A0(sig00000167),
    .A1(sig00000168),
    .A2(sig00000169),
    .A3(sig0000016a),
    .A4(sig0000016b),
    .A5(sig0000016c),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig0000017c)
  );
  RAM64X1S #(
    .INIT ( 64'hE0F07C3E0F07C3E0 ))
  blk0000022e (
    .A0(sig00000167),
    .A1(sig00000168),
    .A2(sig00000169),
    .A3(sig0000016a),
    .A4(sig0000016b),
    .A5(sig0000016c),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig0000017b)
  );
  RAM64X1S #(
    .INIT ( 64'h98CE63398CE63398 ))
  blk0000022f (
    .A0(sig00000167),
    .A1(sig00000168),
    .A2(sig00000169),
    .A3(sig0000016a),
    .A4(sig0000016b),
    .A5(sig0000016c),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig0000017a)
  );
  RAM64X1S #(
    .INIT ( 64'h54A952A54A952A54 ))
  blk00000230 (
    .A0(sig00000167),
    .A1(sig00000168),
    .A2(sig00000169),
    .A3(sig0000016a),
    .A4(sig0000016b),
    .A5(sig0000016c),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig00000179)
  );
  RAM64X1S #(
    .INIT ( 64'h1E3C7870E1C3870E ))
  blk00000231 (
    .A0(sig00000167),
    .A1(sig00000168),
    .A2(sig00000169),
    .A3(sig0000016a),
    .A4(sig0000016b),
    .A5(sig0000016c),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig00000178)
  );
  RAM64X1S #(
    .INIT ( 64'h664C99B366CC9932 ))
  blk00000232 (
    .A0(sig00000167),
    .A1(sig00000168),
    .A2(sig00000169),
    .A3(sig0000016a),
    .A4(sig0000016b),
    .A5(sig0000016c),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig00000177)
  );
  RAM64X1S #(
    .INIT ( 64'h2AD52AD5AA55AA54 ))
  blk00000233 (
    .A0(sig00000167),
    .A1(sig00000168),
    .A2(sig00000169),
    .A3(sig0000016a),
    .A4(sig0000016b),
    .A5(sig0000016c),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig00000176)
  );
  RAM64X1S #(
    .INIT ( 64'h878787870F0F0F0E ))
  blk00000234 (
    .A0(sig00000167),
    .A1(sig00000168),
    .A2(sig00000169),
    .A3(sig0000016a),
    .A4(sig0000016b),
    .A5(sig0000016c),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig00000175)
  );
  RAM64X1S #(
    .INIT ( 64'h9999999933333332 ))
  blk00000235 (
    .A0(sig00000167),
    .A1(sig00000168),
    .A2(sig00000169),
    .A3(sig0000016a),
    .A4(sig0000016b),
    .A5(sig0000016c),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig00000174)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000236 (
    .C(clk),
    .CE(sig00000001),
    .D(sig0000017e),
    .R(sig000000a0),
    .Q(sig000000f4)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000237 (
    .C(clk),
    .CE(sig00000001),
    .D(sig0000017d),
    .R(sig000000a0),
    .Q(sig000000f5)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000238 (
    .C(clk),
    .CE(sig00000001),
    .D(sig0000017c),
    .R(sig000000a0),
    .Q(sig000000f6)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000239 (
    .C(clk),
    .CE(sig00000001),
    .D(sig0000017b),
    .R(sig000000a0),
    .Q(sig000000f7)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000023a (
    .C(clk),
    .CE(sig00000001),
    .D(sig0000017a),
    .R(sig000000a0),
    .Q(sig000000f8)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000023b (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000179),
    .R(sig000000a0),
    .Q(sig000000f9)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000023c (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000178),
    .R(sig000000a0),
    .Q(sig000000fa)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000023d (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000177),
    .R(sig000000a0),
    .Q(sig000000fb)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000023e (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000176),
    .R(sig000000a0),
    .Q(sig000000fc)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000023f (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000175),
    .R(sig000000a0),
    .Q(sig000000fd)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000240 (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000174),
    .R(sig000000a0),
    .Q(sig000000fe)
  );
  RAM64X1S #(
    .INIT ( 64'hFFFFFFC000000000 ))
  blk00000241 (
    .A0(sig0000016d),
    .A1(sig0000016e),
    .A2(sig0000016f),
    .A3(sig00000170),
    .A4(sig00000171),
    .A5(sig00000172),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig0000018f)
  );
  RAM64X1S #(
    .INIT ( 64'hFF00003FFFF80000 ))
  blk00000242 (
    .A0(sig0000016d),
    .A1(sig0000016e),
    .A2(sig0000016f),
    .A3(sig00000170),
    .A4(sig00000171),
    .A5(sig00000172),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig0000018e)
  );
  RAM64X1S #(
    .INIT ( 64'h00FF803FF007FC00 ))
  blk00000243 (
    .A0(sig0000016d),
    .A1(sig0000016e),
    .A2(sig0000016f),
    .A3(sig00000170),
    .A4(sig00000171),
    .A5(sig00000172),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig0000018d)
  );
  RAM64X1S #(
    .INIT ( 64'hE0F07C3E0F07C3E0 ))
  blk00000244 (
    .A0(sig0000016d),
    .A1(sig0000016e),
    .A2(sig0000016f),
    .A3(sig00000170),
    .A4(sig00000171),
    .A5(sig00000172),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig0000018c)
  );
  RAM64X1S #(
    .INIT ( 64'h98CE63398CE63398 ))
  blk00000245 (
    .A0(sig0000016d),
    .A1(sig0000016e),
    .A2(sig0000016f),
    .A3(sig00000170),
    .A4(sig00000171),
    .A5(sig00000172),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig0000018b)
  );
  RAM64X1S #(
    .INIT ( 64'h54A952A54A952A54 ))
  blk00000246 (
    .A0(sig0000016d),
    .A1(sig0000016e),
    .A2(sig0000016f),
    .A3(sig00000170),
    .A4(sig00000171),
    .A5(sig00000172),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig0000018a)
  );
  RAM64X1S #(
    .INIT ( 64'h1E3C7870E1C3870E ))
  blk00000247 (
    .A0(sig0000016d),
    .A1(sig0000016e),
    .A2(sig0000016f),
    .A3(sig00000170),
    .A4(sig00000171),
    .A5(sig00000172),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig00000189)
  );
  RAM64X1S #(
    .INIT ( 64'h664C99B366CC9932 ))
  blk00000248 (
    .A0(sig0000016d),
    .A1(sig0000016e),
    .A2(sig0000016f),
    .A3(sig00000170),
    .A4(sig00000171),
    .A5(sig00000172),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig00000188)
  );
  RAM64X1S #(
    .INIT ( 64'h2AD52AD5AA55AA54 ))
  blk00000249 (
    .A0(sig0000016d),
    .A1(sig0000016e),
    .A2(sig0000016f),
    .A3(sig00000170),
    .A4(sig00000171),
    .A5(sig00000172),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig00000187)
  );
  RAM64X1S #(
    .INIT ( 64'h878787870F0F0F0E ))
  blk0000024a (
    .A0(sig0000016d),
    .A1(sig0000016e),
    .A2(sig0000016f),
    .A3(sig00000170),
    .A4(sig00000171),
    .A5(sig00000172),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig00000186)
  );
  RAM64X1S #(
    .INIT ( 64'h9999999933333332 ))
  blk0000024b (
    .A0(sig0000016d),
    .A1(sig0000016e),
    .A2(sig0000016f),
    .A3(sig00000170),
    .A4(sig00000171),
    .A5(sig00000172),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig00000185)
  );
  RAM64X1S #(
    .INIT ( 64'hAAAAAAAB55555554 ))
  blk0000024c (
    .A0(sig0000016d),
    .A1(sig0000016e),
    .A2(sig0000016f),
    .A3(sig00000170),
    .A4(sig00000171),
    .A5(sig00000172),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig00000184)
  );
  RAM64X1S #(
    .INIT ( 64'h0001FFFE0001FFFE ))
  blk0000024d (
    .A0(sig0000016d),
    .A1(sig0000016e),
    .A2(sig0000016f),
    .A3(sig00000170),
    .A4(sig00000171),
    .A5(sig00000172),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig00000183)
  );
  RAM64X1S #(
    .INIT ( 64'h01FE01FE01FE01FE ))
  blk0000024e (
    .A0(sig0000016d),
    .A1(sig0000016e),
    .A2(sig0000016f),
    .A3(sig00000170),
    .A4(sig00000171),
    .A5(sig00000172),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig00000182)
  );
  RAM64X1S #(
    .INIT ( 64'h6666666666666666 ))
  blk0000024f (
    .A0(sig0000016d),
    .A1(sig0000016e),
    .A2(sig0000016f),
    .A3(sig00000170),
    .A4(sig00000171),
    .A5(sig00000172),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig00000180)
  );
  RAM64X1S #(
    .INIT ( 64'hAAAAAAAAAAAAAAAA ))
  blk00000250 (
    .A0(sig0000016d),
    .A1(sig0000016e),
    .A2(sig0000016f),
    .A3(sig00000170),
    .A4(sig00000171),
    .A5(sig00000172),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig0000017f)
  );
  RAM64X1S #(
    .INIT ( 64'h1E1E1E1E1E1E1E1E ))
  blk00000251 (
    .A0(sig0000016d),
    .A1(sig0000016e),
    .A2(sig0000016f),
    .A3(sig00000170),
    .A4(sig00000171),
    .A5(sig00000172),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig00000181)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000252 (
    .C(clk),
    .CE(sig00000001),
    .D(sig0000018f),
    .R(sig000000a0),
    .Q(sig000000ff)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000253 (
    .C(clk),
    .CE(sig00000001),
    .D(sig0000018e),
    .R(sig000000a0),
    .Q(sig00000100)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000254 (
    .C(clk),
    .CE(sig00000001),
    .D(sig0000018d),
    .R(sig000000a0),
    .Q(sig00000101)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000255 (
    .C(clk),
    .CE(sig00000001),
    .D(sig0000018c),
    .R(sig000000a0),
    .Q(sig00000102)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000256 (
    .C(clk),
    .CE(sig00000001),
    .D(sig0000018b),
    .R(sig000000a0),
    .Q(sig00000103)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000257 (
    .C(clk),
    .CE(sig00000001),
    .D(sig0000018a),
    .R(sig000000a0),
    .Q(sig00000104)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000258 (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000189),
    .R(sig000000a0),
    .Q(sig00000105)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000259 (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000188),
    .R(sig000000a0),
    .Q(sig00000106)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000025a (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000187),
    .R(sig000000a0),
    .Q(sig00000107)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000025b (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000186),
    .R(sig000000a0),
    .Q(sig00000108)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000025c (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000185),
    .R(sig000000a0),
    .Q(sig00000109)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000025d (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000184),
    .R(sig000000a0),
    .Q(sig0000010a)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000025e (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000183),
    .R(sig000000a0),
    .Q(sig0000010b)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk0000025f (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000182),
    .R(sig000000a0),
    .Q(sig0000010c)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000260 (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000181),
    .R(sig000000a0),
    .Q(sig0000010d)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000261 (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000180),
    .R(sig000000a0),
    .Q(sig0000010e)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk00000262 (
    .C(clk),
    .CE(sig00000001),
    .D(sig0000017f),
    .R(sig000000a0),
    .Q(sig0000010f)
  );
  XORCY   blk00000263 (
    .CI(sig00000191),
    .LI(sig000001dc),
    .O(sig000001b6)
  );
  MUXCY   blk00000264 (
    .CI(sig00000191),
    .DI(sig000000a0),
    .S(sig000001dc),
    .O(sig00000190)
  );
  XORCY   blk00000265 (
    .CI(sig00000192),
    .LI(sig000001dd),
    .O(sig000001b5)
  );
  MUXCY   blk00000266 (
    .CI(sig00000192),
    .DI(sig000000a0),
    .S(sig000001dd),
    .O(sig00000191)
  );
  XORCY   blk00000267 (
    .CI(sig00000193),
    .LI(sig000001de),
    .O(sig000001b4)
  );
  MUXCY   blk00000268 (
    .CI(sig00000193),
    .DI(sig000000a0),
    .S(sig000001de),
    .O(sig00000192)
  );
  XORCY   blk00000269 (
    .CI(sig00000194),
    .LI(sig000001df),
    .O(sig000001b3)
  );
  MUXCY   blk0000026a (
    .CI(sig00000194),
    .DI(sig000000a0),
    .S(sig000001df),
    .O(sig00000193)
  );
  XORCY   blk0000026b (
    .CI(sig00000195),
    .LI(sig000001e0),
    .O(sig000001b2)
  );
  MUXCY   blk0000026c (
    .CI(sig00000195),
    .DI(sig000000a0),
    .S(sig000001e0),
    .O(sig00000194)
  );
  XORCY   blk0000026d (
    .CI(sig00000196),
    .LI(sig000001e1),
    .O(sig000001b1)
  );
  MUXCY   blk0000026e (
    .CI(sig00000196),
    .DI(sig000000a0),
    .S(sig000001e1),
    .O(sig00000195)
  );
  XORCY   blk0000026f (
    .CI(sig00000198),
    .LI(sig00000197),
    .O(sig000001b0)
  );
  MUXCY   blk00000270 (
    .CI(sig00000198),
    .DI(sig000000f4),
    .S(sig00000197),
    .O(sig00000196)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk00000271 (
    .I0(sig000000f4),
    .I1(sig00000105),
    .O(sig00000197)
  );
  XORCY   blk00000272 (
    .CI(sig0000019a),
    .LI(sig00000199),
    .O(sig000001af)
  );
  MUXCY   blk00000273 (
    .CI(sig0000019a),
    .DI(sig000000f5),
    .S(sig00000199),
    .O(sig00000198)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk00000274 (
    .I0(sig000000f5),
    .I1(sig00000106),
    .O(sig00000199)
  );
  XORCY   blk00000275 (
    .CI(sig0000019c),
    .LI(sig0000019b),
    .O(sig000001ae)
  );
  MUXCY   blk00000276 (
    .CI(sig0000019c),
    .DI(sig000000f6),
    .S(sig0000019b),
    .O(sig0000019a)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk00000277 (
    .I0(sig000000f6),
    .I1(sig00000107),
    .O(sig0000019b)
  );
  XORCY   blk00000278 (
    .CI(sig0000019e),
    .LI(sig0000019d),
    .O(sig000001ad)
  );
  MUXCY   blk00000279 (
    .CI(sig0000019e),
    .DI(sig000000f7),
    .S(sig0000019d),
    .O(sig0000019c)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk0000027a (
    .I0(sig000000f7),
    .I1(sig00000108),
    .O(sig0000019d)
  );
  XORCY   blk0000027b (
    .CI(sig000001a0),
    .LI(sig0000019f),
    .O(sig000001ac)
  );
  MUXCY   blk0000027c (
    .CI(sig000001a0),
    .DI(sig000000f8),
    .S(sig0000019f),
    .O(sig0000019e)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk0000027d (
    .I0(sig000000f8),
    .I1(sig00000109),
    .O(sig0000019f)
  );
  MUXCY   blk0000027e (
    .CI(sig000001a2),
    .DI(sig000000f9),
    .S(sig000001a1),
    .O(sig000001a0)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk0000027f (
    .I0(sig000000f9),
    .I1(sig0000010a),
    .O(sig000001a1)
  );
  MUXCY   blk00000280 (
    .CI(sig000001a4),
    .DI(sig000000fa),
    .S(sig000001a3),
    .O(sig000001a2)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk00000281 (
    .I0(sig000000fa),
    .I1(sig0000010b),
    .O(sig000001a3)
  );
  MUXCY   blk00000282 (
    .CI(sig000001a6),
    .DI(sig000000fb),
    .S(sig000001a5),
    .O(sig000001a4)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk00000283 (
    .I0(sig000000fb),
    .I1(sig0000010c),
    .O(sig000001a5)
  );
  MUXCY   blk00000284 (
    .CI(sig000001a8),
    .DI(sig000000fc),
    .S(sig000001a7),
    .O(sig000001a6)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk00000285 (
    .I0(sig000000fc),
    .I1(sig0000010d),
    .O(sig000001a7)
  );
  MUXCY   blk00000286 (
    .CI(sig000001aa),
    .DI(sig000000fd),
    .S(sig000001a9),
    .O(sig000001a8)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk00000287 (
    .I0(sig000000fd),
    .I1(sig0000010e),
    .O(sig000001a9)
  );
  MUXCY   blk00000288 (
    .CI(sig000000a0),
    .DI(sig000000fe),
    .S(sig000001ab),
    .O(sig000001aa)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk00000289 (
    .I0(sig000000fe),
    .I1(sig0000010f),
    .O(sig000001ab)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk0000028a (
    .C(clk),
    .D(sig00000190),
    .Q(sig00000110)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk0000028b (
    .C(clk),
    .D(sig000001b6),
    .Q(sig00000111)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk0000028c (
    .C(clk),
    .D(sig000001b5),
    .Q(sig00000112)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk0000028d (
    .C(clk),
    .D(sig000001b4),
    .Q(sig00000113)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk0000028e (
    .C(clk),
    .D(sig000001b3),
    .Q(sig00000114)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk0000028f (
    .C(clk),
    .D(sig000001b2),
    .Q(sig00000115)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000290 (
    .C(clk),
    .D(sig000001b1),
    .Q(sig00000116)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000291 (
    .C(clk),
    .D(sig000001b0),
    .Q(sig00000117)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000292 (
    .C(clk),
    .D(sig000001af),
    .Q(sig00000118)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000293 (
    .C(clk),
    .D(sig000001ae),
    .Q(sig00000119)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000294 (
    .C(clk),
    .D(sig000001ad),
    .Q(sig0000011a)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000295 (
    .C(clk),
    .D(sig000001ac),
    .Q(sig0000011b)
  );
  RAM64X1S #(
    .INIT ( 64'h0000000000000000 ))
  blk00000296 (
    .A0(sig00000173),
    .A1(sig000000a0),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .A4(sig000000a0),
    .A5(sig000000a0),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig000001b7)
  );
  RAM64X1S #(
    .INIT ( 64'hAAAAAAAAAAAAAAAA ))
  blk00000297 (
    .A0(sig00000173),
    .A1(sig000000a0),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .A4(sig000000a0),
    .A5(sig000000a0),
    .D(sig000000a0),
    .WCLK(clk),
    .WE(sig000000a0),
    .O(sig000001b8)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000298 (
    .C(clk),
    .D(sig000001b8),
    .Q(sig0000011d)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk00000299 (
    .C(clk),
    .D(sig000001b7),
    .Q(sig0000011c)
  );
  XORCY   blk000002a7 (
    .CI(sig000001ba),
    .LI(sig000001b9),
    .O(sig000001d9)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk000002a8 (
    .I0(sig00000110),
    .I1(sig0000011e),
    .O(sig000001b9)
  );
  XORCY   blk000002a9 (
    .CI(sig000001bc),
    .LI(sig000001bb),
    .O(sig000001d8)
  );
  MUXCY   blk000002aa (
    .CI(sig000001bc),
    .DI(sig00000111),
    .S(sig000001bb),
    .O(sig000001ba)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk000002ab (
    .I0(sig00000111),
    .I1(sig0000011f),
    .O(sig000001bb)
  );
  XORCY   blk000002ac (
    .CI(sig000001be),
    .LI(sig000001bd),
    .O(sig000001d7)
  );
  MUXCY   blk000002ad (
    .CI(sig000001be),
    .DI(sig00000112),
    .S(sig000001bd),
    .O(sig000001bc)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk000002ae (
    .I0(sig00000112),
    .I1(sig00000120),
    .O(sig000001bd)
  );
  XORCY   blk000002af (
    .CI(sig000001c0),
    .LI(sig000001bf),
    .O(sig000001d6)
  );
  MUXCY   blk000002b0 (
    .CI(sig000001c0),
    .DI(sig00000113),
    .S(sig000001bf),
    .O(sig000001be)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk000002b1 (
    .I0(sig00000113),
    .I1(sig00000121),
    .O(sig000001bf)
  );
  XORCY   blk000002b2 (
    .CI(sig000001c2),
    .LI(sig000001c1),
    .O(sig000001d5)
  );
  MUXCY   blk000002b3 (
    .CI(sig000001c2),
    .DI(sig00000114),
    .S(sig000001c1),
    .O(sig000001c0)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk000002b4 (
    .I0(sig00000114),
    .I1(sig00000122),
    .O(sig000001c1)
  );
  XORCY   blk000002b5 (
    .CI(sig000001c4),
    .LI(sig000001c3),
    .O(sig000001d4)
  );
  MUXCY   blk000002b6 (
    .CI(sig000001c4),
    .DI(sig00000115),
    .S(sig000001c3),
    .O(sig000001c2)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk000002b7 (
    .I0(sig00000115),
    .I1(sig00000123),
    .O(sig000001c3)
  );
  XORCY   blk000002b8 (
    .CI(sig000001c6),
    .LI(sig000001c5),
    .O(sig000001d3)
  );
  MUXCY   blk000002b9 (
    .CI(sig000001c6),
    .DI(sig00000116),
    .S(sig000001c5),
    .O(sig000001c4)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk000002ba (
    .I0(sig00000116),
    .I1(sig00000124),
    .O(sig000001c5)
  );
  XORCY   blk000002bb (
    .CI(sig000001c8),
    .LI(sig000001c7),
    .O(sig000001d2)
  );
  MUXCY   blk000002bc (
    .CI(sig000001c8),
    .DI(sig00000117),
    .S(sig000001c7),
    .O(sig000001c6)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk000002bd (
    .I0(sig00000117),
    .I1(sig00000125),
    .O(sig000001c7)
  );
  XORCY   blk000002be (
    .CI(sig000001ca),
    .LI(sig000001c9),
    .O(sig000001d1)
  );
  MUXCY   blk000002bf (
    .CI(sig000001ca),
    .DI(sig00000118),
    .S(sig000001c9),
    .O(sig000001c8)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk000002c0 (
    .I0(sig00000118),
    .I1(sig00000126),
    .O(sig000001c9)
  );
  XORCY   blk000002c1 (
    .CI(sig000001cc),
    .LI(sig000001cb),
    .O(sig000001d0)
  );
  MUXCY   blk000002c2 (
    .CI(sig000001cc),
    .DI(sig00000119),
    .S(sig000001cb),
    .O(sig000001ca)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk000002c3 (
    .I0(sig00000119),
    .I1(sig00000127),
    .O(sig000001cb)
  );
  MUXCY   blk000002c4 (
    .CI(sig000001ce),
    .DI(sig0000011a),
    .S(sig000001cd),
    .O(sig000001cc)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk000002c5 (
    .I0(sig0000011a),
    .I1(sig00000128),
    .O(sig000001cd)
  );
  MUXCY   blk000002c6 (
    .CI(sig000000a0),
    .DI(sig0000011b),
    .S(sig000001cf),
    .O(sig000001ce)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk000002c7 (
    .I0(sig0000011b),
    .I1(sig00000129),
    .O(sig000001cf)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk000002c8 (
    .C(clk),
    .D(sig000001d9),
    .Q(sig0000012a)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk000002c9 (
    .C(clk),
    .D(sig000001d8),
    .Q(sig0000012b)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk000002ca (
    .C(clk),
    .D(sig000001d7),
    .Q(sig0000012c)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk000002cb (
    .C(clk),
    .D(sig000001d6),
    .Q(sig0000012d)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk000002cc (
    .C(clk),
    .D(sig000001d5),
    .Q(sig0000012e)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk000002cd (
    .C(clk),
    .D(sig000001d4),
    .Q(sig0000012f)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk000002ce (
    .C(clk),
    .D(sig000001d3),
    .Q(sig00000130)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk000002cf (
    .C(clk),
    .D(sig000001d2),
    .Q(sig00000131)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk000002d0 (
    .C(clk),
    .D(sig000001d1),
    .Q(sig00000132)
  );
  FD #(
    .INIT ( 1'b0 ))
  blk000002d1 (
    .C(clk),
    .D(sig000001d0),
    .Q(sig00000133)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000002d3 (
    .C(clk),
    .CE(sig00000137),
    .D(sig0000012a),
    .R(sig000000a0),
    .Q(\U0/i_synth/gen_cordic.output_stage/gen_x_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [9])
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000002d4 (
    .C(clk),
    .CE(sig00000137),
    .D(sig0000012b),
    .R(sig000000a0),
    .Q(\U0/i_synth/gen_cordic.output_stage/gen_x_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [8])
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000002d5 (
    .C(clk),
    .CE(sig00000137),
    .D(sig0000012c),
    .R(sig000000a0),
    .Q(\U0/i_synth/gen_cordic.output_stage/gen_x_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [7])
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000002d6 (
    .C(clk),
    .CE(sig00000137),
    .D(sig0000012d),
    .R(sig000000a0),
    .Q(\U0/i_synth/gen_cordic.output_stage/gen_x_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [6])
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000002d7 (
    .C(clk),
    .CE(sig00000137),
    .D(sig0000012e),
    .R(sig000000a0),
    .Q(\U0/i_synth/gen_cordic.output_stage/gen_x_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [5])
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000002d8 (
    .C(clk),
    .CE(sig00000137),
    .D(sig0000012f),
    .R(sig000000a0),
    .Q(\U0/i_synth/gen_cordic.output_stage/gen_x_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [4])
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000002d9 (
    .C(clk),
    .CE(sig00000137),
    .D(sig00000130),
    .R(sig000000a0),
    .Q(\U0/i_synth/gen_cordic.output_stage/gen_x_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [3])
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000002da (
    .C(clk),
    .CE(sig00000137),
    .D(sig00000131),
    .R(sig000000a0),
    .Q(\U0/i_synth/gen_cordic.output_stage/gen_x_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [2])
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000002db (
    .C(clk),
    .CE(sig00000137),
    .D(sig00000132),
    .R(sig000000a0),
    .Q(\U0/i_synth/gen_cordic.output_stage/gen_x_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [1])
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000002dc (
    .C(clk),
    .CE(sig00000137),
    .D(sig00000133),
    .R(sig000000a0),
    .Q(\U0/i_synth/gen_cordic.output_stage/gen_x_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [0])
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000002dd (
    .C(clk),
    .CE(sig00000137),
    .D(sig00000141),
    .R(sig000000a0),
    .Q(\U0/i_synth/gen_cordic.output_stage/gen_phase_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [9])
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000002de (
    .C(clk),
    .CE(sig00000137),
    .D(sig00000140),
    .R(sig000000a0),
    .Q(\U0/i_synth/gen_cordic.output_stage/gen_phase_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [8])
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000002df (
    .C(clk),
    .CE(sig00000137),
    .D(sig0000013f),
    .R(sig000000a0),
    .Q(\U0/i_synth/gen_cordic.output_stage/gen_phase_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [7])
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000002e0 (
    .C(clk),
    .CE(sig00000137),
    .D(sig0000013e),
    .R(sig000000a0),
    .Q(\U0/i_synth/gen_cordic.output_stage/gen_phase_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [6])
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000002e1 (
    .C(clk),
    .CE(sig00000137),
    .D(sig0000013d),
    .R(sig000000a0),
    .Q(\U0/i_synth/gen_cordic.output_stage/gen_phase_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [5])
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000002e2 (
    .C(clk),
    .CE(sig00000137),
    .D(sig0000013c),
    .R(sig000000a0),
    .Q(\U0/i_synth/gen_cordic.output_stage/gen_phase_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [4])
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000002e3 (
    .C(clk),
    .CE(sig00000137),
    .D(sig0000013b),
    .R(sig000000a0),
    .Q(\U0/i_synth/gen_cordic.output_stage/gen_phase_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [3])
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000002e4 (
    .C(clk),
    .CE(sig00000137),
    .D(sig0000013a),
    .R(sig000000a0),
    .Q(\U0/i_synth/gen_cordic.output_stage/gen_phase_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [2])
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000002e5 (
    .C(clk),
    .CE(sig00000137),
    .D(sig00000139),
    .R(sig000000a0),
    .Q(\U0/i_synth/gen_cordic.output_stage/gen_phase_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [1])
  );
  FDRE #(
    .INIT ( 1'b0 ))
  blk000002e6 (
    .C(clk),
    .CE(sig00000137),
    .D(sig00000138),
    .R(sig000000a0),
    .Q(\U0/i_synth/gen_cordic.output_stage/gen_phase_out.round/gen_truncate.gen_round_out/gen_rtl.gen_reg.d_reg [0])
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk000002e7 (
    .I0(sig00000037),
    .I1(sig0000001b),
    .I2(sig000001e2),
    .O(sig00000077)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk000002e8 (
    .I0(sig00000036),
    .I1(sig0000001a),
    .I2(sig000001e2),
    .O(sig00000076)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk000002e9 (
    .I0(sig00000035),
    .I1(sig00000019),
    .I2(sig000001e5),
    .O(sig00000075)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk000002ea (
    .I0(sig00000034),
    .I1(sig00000018),
    .I2(sig000001e5),
    .O(sig00000074)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk000002eb (
    .I0(sig00000033),
    .I1(sig00000017),
    .I2(sig000001e5),
    .O(sig00000073)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk000002ec (
    .I0(sig00000032),
    .I1(sig00000016),
    .I2(sig000001e5),
    .O(sig00000072)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk000002ed (
    .I0(sig00000031),
    .I1(sig00000015),
    .I2(sig000001e5),
    .O(sig00000071)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk000002ee (
    .I0(sig00000030),
    .I1(sig00000014),
    .I2(sig0000004f),
    .O(sig00000070)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk000002ef (
    .I0(sig0000002f),
    .I1(sig00000013),
    .I2(sig0000004f),
    .O(sig0000006f)
  );
  LUT3 #(
    .INIT ( 8'hD8 ))
  blk000002f0 (
    .I0(sig000001e3),
    .I1(sig0000003a),
    .I2(sig0000001e),
    .O(sig00000051)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk000002f1 (
    .I0(sig00000039),
    .I1(sig0000001d),
    .I2(sig000001e2),
    .O(sig00000079)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk000002f2 (
    .I0(sig00000038),
    .I1(sig0000001c),
    .I2(sig000001e2),
    .O(sig00000078)
  );
  LUT2 #(
    .INIT ( 4'h4 ))
  blk000002f3 (
    .I0(sig0000004f),
    .I1(sig00000012),
    .O(sig0000006e)
  );
  LUT2 #(
    .INIT ( 4'h4 ))
  blk000002f4 (
    .I0(sig0000004f),
    .I1(sig0000000e),
    .O(sig00000090)
  );
  LUT2 #(
    .INIT ( 4'h4 ))
  blk000002f5 (
    .I0(sig0000004f),
    .I1(sig0000000d),
    .O(sig0000008f)
  );
  LUT2 #(
    .INIT ( 4'h4 ))
  blk000002f6 (
    .I0(sig0000004f),
    .I1(sig0000000c),
    .O(sig0000008e)
  );
  LUT2 #(
    .INIT ( 4'h4 ))
  blk000002f7 (
    .I0(sig0000004f),
    .I1(sig0000000b),
    .O(sig0000008d)
  );
  LUT2 #(
    .INIT ( 4'h4 ))
  blk000002f8 (
    .I0(sig0000004f),
    .I1(sig0000000a),
    .O(sig0000008c)
  );
  LUT2 #(
    .INIT ( 4'h4 ))
  blk000002f9 (
    .I0(sig0000004f),
    .I1(sig00000009),
    .O(sig0000008b)
  );
  LUT2 #(
    .INIT ( 4'h4 ))
  blk000002fa (
    .I0(sig0000004f),
    .I1(sig00000008),
    .O(sig0000008a)
  );
  LUT2 #(
    .INIT ( 4'h4 ))
  blk000002fb (
    .I0(sig0000004f),
    .I1(sig00000007),
    .O(sig00000089)
  );
  LUT2 #(
    .INIT ( 4'h4 ))
  blk000002fc (
    .I0(sig0000004f),
    .I1(sig00000006),
    .O(sig00000088)
  );
  LUT2 #(
    .INIT ( 4'h4 ))
  blk000002fd (
    .I0(sig0000004f),
    .I1(sig00000011),
    .O(sig00000093)
  );
  LUT2 #(
    .INIT ( 4'h4 ))
  blk000002fe (
    .I0(sig0000004f),
    .I1(sig00000010),
    .O(sig00000092)
  );
  LUT2 #(
    .INIT ( 4'h4 ))
  blk000002ff (
    .I0(sig0000004f),
    .I1(sig0000000f),
    .O(sig00000091)
  );
  LUT2 #(
    .INIT ( 4'h4 ))
  blk00000300 (
    .I0(sig0000004f),
    .I1(sig00000005),
    .O(sig00000087)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk00000301 (
    .I0(sig00000043),
    .I1(sig00000028),
    .I2(sig000001e2),
    .O(sig00000083)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk00000302 (
    .I0(sig00000042),
    .I1(sig00000027),
    .I2(sig000001e2),
    .O(sig00000082)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk00000303 (
    .I0(sig00000041),
    .I1(sig00000026),
    .I2(sig000001e5),
    .O(sig00000081)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk00000304 (
    .I0(sig00000040),
    .I1(sig00000025),
    .I2(sig000001e5),
    .O(sig00000080)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk00000305 (
    .I0(sig0000003f),
    .I1(sig00000024),
    .I2(sig000001e5),
    .O(sig0000007f)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk00000306 (
    .I0(sig0000003e),
    .I1(sig00000023),
    .I2(sig000001e5),
    .O(sig0000007e)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk00000307 (
    .I0(sig0000003d),
    .I1(sig00000022),
    .I2(sig000001e5),
    .O(sig0000007d)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk00000308 (
    .I0(sig0000003c),
    .I1(sig00000021),
    .I2(sig0000004f),
    .O(sig0000007c)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk00000309 (
    .I0(sig0000003b),
    .I1(sig00000020),
    .I2(sig0000004f),
    .O(sig0000007b)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk0000030a (
    .I0(sig00000046),
    .I1(sig0000002b),
    .I2(sig000001e5),
    .O(sig00000086)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk0000030b (
    .I0(sig00000045),
    .I1(sig0000002a),
    .I2(sig000001e2),
    .O(sig00000085)
  );
  LUT3 #(
    .INIT ( 8'hAC ))
  blk0000030c (
    .I0(sig00000044),
    .I1(sig00000029),
    .I2(sig000001e2),
    .O(sig00000084)
  );
  LUT2 #(
    .INIT ( 4'h4 ))
  blk0000030d (
    .I0(sig0000004f),
    .I1(sig0000001f),
    .O(sig0000007a)
  );
  LUT6 #(
    .INIT ( 64'hFFEFFEEE11011000 ))
  blk0000030e (
    .I0(sig00000053),
    .I1(sig00000054),
    .I2(sig00000052),
    .I3(sig00000079),
    .I4(sig00000078),
    .I5(sig00000051),
    .O(sig00000061)
  );
  LUT5 #(
    .INIT ( 32'hFFFE0100 ))
  blk0000030f (
    .I0(sig00000054),
    .I1(sig00000053),
    .I2(sig00000052),
    .I3(sig00000079),
    .I4(sig00000051),
    .O(sig00000062)
  );
  LUT6 #(
    .INIT ( 64'hFFEFFEEE11011000 ))
  blk00000310 (
    .I0(sig00000053),
    .I1(sig00000054),
    .I2(sig00000052),
    .I3(sig00000085),
    .I4(sig00000084),
    .I5(sig00000086),
    .O(sig0000006c)
  );
  LUT5 #(
    .INIT ( 32'hFFFE0100 ))
  blk00000311 (
    .I0(sig00000054),
    .I1(sig00000053),
    .I2(sig00000052),
    .I3(sig00000085),
    .I4(sig00000086),
    .O(sig0000006d)
  );
  LUT4 #(
    .INIT ( 16'h0400 ))
  blk00000312 (
    .I0(sig000000e1),
    .I1(sig000000e2),
    .I2(sig000000e3),
    .I3(sig000000e4),
    .O(sig000000df)
  );
  LUT3 #(
    .INIT ( 8'hBA ))
  blk00000313 (
    .I0(sig00000002),
    .I1(sig0000002c),
    .I2(sig000000eb),
    .O(NlwRenamedSig_OI_rfd)
  );
  LUT2 #(
    .INIT ( 4'h8 ))
  blk00000314 (
    .I0(sig0000002c),
    .I1(sig000000eb),
    .O(sig000000e9)
  );
  LUT3 #(
    .INIT ( 8'h29 ))
  blk00000315 (
    .I0(sig00000055),
    .I1(sig00000056),
    .I2(sig00000057),
    .O(sig000000f1)
  );
  LUT3 #(
    .INIT ( 8'h14 ))
  blk00000316 (
    .I0(sig00000055),
    .I1(sig00000056),
    .I2(sig00000057),
    .O(sig000000f0)
  );
  LUT3 #(
    .INIT ( 8'h01 ))
  blk00000317 (
    .I0(sig00000055),
    .I1(sig00000056),
    .I2(sig00000057),
    .O(sig000000ec)
  );
  LUT3 #(
    .INIT ( 8'h51 ))
  blk00000318 (
    .I0(sig00000057),
    .I1(sig00000056),
    .I2(sig00000055),
    .O(sig000000ef)
  );
  LUT3 #(
    .INIT ( 8'h51 ))
  blk00000319 (
    .I0(sig00000055),
    .I1(sig00000056),
    .I2(sig00000057),
    .O(sig000000f2)
  );
  LUT3 #(
    .INIT ( 8'hB9 ))
  blk0000031a (
    .I0(sig00000057),
    .I1(sig00000055),
    .I2(sig00000056),
    .O(sig000000f3)
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  blk0000031b (
    .I0(sig00000055),
    .I1(sig00000056),
    .I2(sig00000057),
    .O(sig000000ed)
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  blk0000031c (
    .I0(sig00000056),
    .I1(sig00000055),
    .I2(sig00000057),
    .O(sig000000ee)
  );
  LUT2 #(
    .INIT ( 4'h7 ))
  blk0000031d (
    .I0(sig00000004),
    .I1(sig00000003),
    .O(sig00000134)
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  blk0000031e (
    .I0(sig00000004),
    .I1(sig00000003),
    .O(sig00000135)
  );
  LUT3 #(
    .INIT ( 8'hAB ))
  blk0000031f (
    .I0(sig00000004),
    .I1(sig00000011),
    .I2(sig00000003),
    .O(sig00000136)
  );
  LUT6 #(
    .INIT ( 64'hFFEFFAEA15051000 ))
  blk00000320 (
    .I0(sig00000054),
    .I1(sig00000053),
    .I2(sig00000052),
    .I3(sig00000078),
    .I4(sig000001da),
    .I5(sig00000051),
    .O(sig00000060)
  );
  LUT6 #(
    .INIT ( 64'hFFFB1511EEEA0400 ))
  blk00000321 (
    .I0(sig00000054),
    .I1(sig00000052),
    .I2(sig00000053),
    .I3(sig00000084),
    .I4(sig00000086),
    .I5(sig000001db),
    .O(sig0000006b)
  );
  LUT1 #(
    .INIT ( 2'h2 ))
  blk00000322 (
    .I0(sig000000ff),
    .O(sig000001dc)
  );
  LUT1 #(
    .INIT ( 2'h2 ))
  blk00000323 (
    .I0(sig00000100),
    .O(sig000001dd)
  );
  LUT1 #(
    .INIT ( 2'h2 ))
  blk00000324 (
    .I0(sig00000101),
    .O(sig000001de)
  );
  LUT1 #(
    .INIT ( 2'h2 ))
  blk00000325 (
    .I0(sig00000102),
    .O(sig000001df)
  );
  LUT1 #(
    .INIT ( 2'h2 ))
  blk00000326 (
    .I0(sig00000103),
    .O(sig000001e0)
  );
  LUT1 #(
    .INIT ( 2'h2 ))
  blk00000327 (
    .I0(sig00000104),
    .O(sig000001e1)
  );
  LUT6 #(
    .INIT ( 64'hFF00F0F0CCCCAAAA ))
  blk00000328 (
    .I0(sig0000001b),
    .I1(sig00000037),
    .I2(sig0000001d),
    .I3(sig00000039),
    .I4(sig0000004f),
    .I5(sig00000053),
    .O(sig000001da)
  );
  LUT6 #(
    .INIT ( 64'hAAAAFF00CCCCF0F0 ))
  blk00000329 (
    .I0(sig00000045),
    .I1(sig00000043),
    .I2(sig00000028),
    .I3(sig0000002a),
    .I4(sig0000004f),
    .I5(sig00000053),
    .O(sig000001db)
  );
  LUT5 #(
    .INIT ( 32'hFD75A820 ))
  blk0000032a (
    .I0(sig00000054),
    .I1(sig0000004f),
    .I2(sig0000001e),
    .I3(sig0000003a),
    .I4(sig000000d5),
    .O(sig0000005f)
  );
  LUT5 #(
    .INIT ( 32'hFD75A820 ))
  blk0000032b (
    .I0(sig00000054),
    .I1(sig0000004f),
    .I2(sig0000002b),
    .I3(sig00000046),
    .I4(sig000000da),
    .O(sig0000006a)
  );
  LUT3 #(
    .INIT ( 8'h53 ))
  blk0000032c (
    .I0(sig0000003a),
    .I1(sig0000001e),
    .I2(sig000001e5),
    .O(sig00000050)
  );
  LUT4 #(
    .INIT ( 16'hF690 ))
  blk0000032d (
    .I0(sig000000c0),
    .I1(sig000000bf),
    .I2(sig000000ab),
    .I3(sig000000b5),
    .O(sig00000096)
  );
  LUT4 #(
    .INIT ( 16'hF690 ))
  blk0000032e (
    .I0(sig000000c0),
    .I1(sig000000bf),
    .I2(sig000000b5),
    .I3(sig000000ab),
    .O(sig000000a1)
  );
  LUT4 #(
    .INIT ( 16'hF690 ))
  blk0000032f (
    .I0(sig000000c0),
    .I1(sig000000bf),
    .I2(sig000000ac),
    .I3(sig000000b6),
    .O(sig00000097)
  );
  LUT4 #(
    .INIT ( 16'hF690 ))
  blk00000330 (
    .I0(sig000000c0),
    .I1(sig000000bf),
    .I2(sig000000b6),
    .I3(sig000000ac),
    .O(sig000000a2)
  );
  LUT4 #(
    .INIT ( 16'hF690 ))
  blk00000331 (
    .I0(sig000000c0),
    .I1(sig000000bf),
    .I2(sig000000ad),
    .I3(sig000000b7),
    .O(sig00000098)
  );
  LUT4 #(
    .INIT ( 16'hF690 ))
  blk00000332 (
    .I0(sig000000c0),
    .I1(sig000000bf),
    .I2(sig000000b7),
    .I3(sig000000ad),
    .O(sig000000a3)
  );
  LUT4 #(
    .INIT ( 16'hF690 ))
  blk00000333 (
    .I0(sig000000c0),
    .I1(sig000000bf),
    .I2(sig000000ae),
    .I3(sig000000b8),
    .O(sig00000099)
  );
  LUT4 #(
    .INIT ( 16'hF690 ))
  blk00000334 (
    .I0(sig000000c0),
    .I1(sig000000bf),
    .I2(sig000000b8),
    .I3(sig000000ae),
    .O(sig000000a4)
  );
  LUT4 #(
    .INIT ( 16'hF690 ))
  blk00000335 (
    .I0(sig000000c0),
    .I1(sig000000bf),
    .I2(sig000000af),
    .I3(sig000000b9),
    .O(sig0000009a)
  );
  LUT4 #(
    .INIT ( 16'hF690 ))
  blk00000336 (
    .I0(sig000000c0),
    .I1(sig000000bf),
    .I2(sig000000b9),
    .I3(sig000000af),
    .O(sig000000a5)
  );
  LUT4 #(
    .INIT ( 16'hF690 ))
  blk00000337 (
    .I0(sig000000c0),
    .I1(sig000000bf),
    .I2(sig000000b0),
    .I3(sig000000ba),
    .O(sig0000009b)
  );
  LUT4 #(
    .INIT ( 16'hF690 ))
  blk00000338 (
    .I0(sig000000c0),
    .I1(sig000000bf),
    .I2(sig000000ba),
    .I3(sig000000b0),
    .O(sig000000a6)
  );
  LUT4 #(
    .INIT ( 16'hF690 ))
  blk00000339 (
    .I0(sig000000c0),
    .I1(sig000000bf),
    .I2(sig000000b1),
    .I3(sig000000bb),
    .O(sig0000009c)
  );
  LUT4 #(
    .INIT ( 16'hF690 ))
  blk0000033a (
    .I0(sig000000c0),
    .I1(sig000000bf),
    .I2(sig000000bb),
    .I3(sig000000b1),
    .O(sig000000a7)
  );
  LUT4 #(
    .INIT ( 16'hF690 ))
  blk0000033b (
    .I0(sig000000c0),
    .I1(sig000000bf),
    .I2(sig000000b2),
    .I3(sig000000bc),
    .O(sig0000009d)
  );
  LUT4 #(
    .INIT ( 16'hF690 ))
  blk0000033c (
    .I0(sig000000c0),
    .I1(sig000000bf),
    .I2(sig000000bc),
    .I3(sig000000b2),
    .O(sig000000a8)
  );
  LUT4 #(
    .INIT ( 16'hF690 ))
  blk0000033d (
    .I0(sig000000c0),
    .I1(sig000000bf),
    .I2(sig000000b3),
    .I3(sig000000bd),
    .O(sig0000009e)
  );
  LUT4 #(
    .INIT ( 16'hF690 ))
  blk0000033e (
    .I0(sig000000c0),
    .I1(sig000000bf),
    .I2(sig000000bd),
    .I3(sig000000b3),
    .O(sig000000a9)
  );
  LUT4 #(
    .INIT ( 16'hF690 ))
  blk0000033f (
    .I0(sig000000c0),
    .I1(sig000000bf),
    .I2(sig000000b4),
    .I3(sig000000be),
    .O(sig0000009f)
  );
  LUT4 #(
    .INIT ( 16'hF690 ))
  blk00000340 (
    .I0(sig000000c0),
    .I1(sig000000bf),
    .I2(sig000000be),
    .I3(sig000000b4),
    .O(sig000000aa)
  );
  LUT4 #(
    .INIT ( 16'hF444 ))
  blk00000341 (
    .I0(sig000000e1),
    .I1(sig000000e7),
    .I2(sig000000eb),
    .I3(sig0000002c),
    .O(sig000000e6)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk00000342 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000e8),
    .Q(sig000001e2)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk00000343 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000e8),
    .Q(sig000001e3)
  );
  LUT3 #(
    .INIT ( 8'hD8 ))
  blk00000344 (
    .I0(sig000001e3),
    .I1(sig0000003a),
    .I2(sig0000001e),
    .O(sig000001e4)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk00000345 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000000e8),
    .Q(sig000001e5)
  );
  MUXF7   blk00000346 (
    .I0(sig000001e6),
    .I1(sig000001e7),
    .S(sig00000054),
    .O(sig0000005d)
  );
  LUT6 #(
    .INIT ( 64'hFD75B931EC64A820 ))
  blk00000347 (
    .I0(sig00000052),
    .I1(sig00000053),
    .I2(sig00000075),
    .I3(sig00000077),
    .I4(sig00000076),
    .I5(sig00000074),
    .O(sig000001e6)
  );
  LUT5 #(
    .INIT ( 32'hEFEA4540 ))
  blk00000348 (
    .I0(sig00000053),
    .I1(sig00000079),
    .I2(sig00000052),
    .I3(sig00000078),
    .I4(sig000001e4),
    .O(sig000001e7)
  );
  MUXF7   blk00000349 (
    .I0(sig000001e8),
    .I1(sig000001e9),
    .S(sig00000054),
    .O(sig00000068)
  );
  LUT6 #(
    .INIT ( 64'hFD75B931EC64A820 ))
  blk0000034a (
    .I0(sig00000052),
    .I1(sig00000053),
    .I2(sig00000081),
    .I3(sig00000083),
    .I4(sig00000082),
    .I5(sig00000080),
    .O(sig000001e8)
  );
  LUT5 #(
    .INIT ( 32'hEFEA4540 ))
  blk0000034b (
    .I0(sig00000053),
    .I1(sig00000085),
    .I2(sig00000052),
    .I3(sig00000084),
    .I4(sig00000086),
    .O(sig000001e9)
  );
  MUXF7   blk0000034c (
    .I0(sig000001ea),
    .I1(sig000001eb),
    .S(sig00000052),
    .O(sig00000058)
  );
  LUT6 #(
    .INIT ( 64'hFD75B931EC64A820 ))
  blk0000034d (
    .I0(sig00000053),
    .I1(sig00000054),
    .I2(sig00000071),
    .I3(sig00000075),
    .I4(sig00000073),
    .I5(sig0000006f),
    .O(sig000001ea)
  );
  LUT6 #(
    .INIT ( 64'hFD75B931EC64A820 ))
  blk0000034e (
    .I0(sig00000053),
    .I1(sig00000054),
    .I2(sig00000072),
    .I3(sig00000076),
    .I4(sig00000074),
    .I5(sig00000070),
    .O(sig000001eb)
  );
  MUXF7   blk0000034f (
    .I0(sig000001ec),
    .I1(sig000001ed),
    .S(sig00000052),
    .O(sig00000063)
  );
  LUT6 #(
    .INIT ( 64'hFD75B931EC64A820 ))
  blk00000350 (
    .I0(sig00000053),
    .I1(sig00000054),
    .I2(sig0000007d),
    .I3(sig00000081),
    .I4(sig0000007f),
    .I5(sig0000007b),
    .O(sig000001ec)
  );
  LUT6 #(
    .INIT ( 64'hFD75B931EC64A820 ))
  blk00000351 (
    .I0(sig00000053),
    .I1(sig00000054),
    .I2(sig0000007e),
    .I3(sig00000082),
    .I4(sig00000080),
    .I5(sig0000007c),
    .O(sig000001ed)
  );
  MUXF7   blk00000352 (
    .I0(sig000001ee),
    .I1(sig000001ef),
    .S(sig00000054),
    .O(sig0000005e)
  );
  LUT6 #(
    .INIT ( 64'hFD75B931EC64A820 ))
  blk00000353 (
    .I0(sig00000053),
    .I1(sig00000052),
    .I2(sig00000077),
    .I3(sig00000078),
    .I4(sig00000076),
    .I5(sig00000075),
    .O(sig000001ee)
  );
  LUT6 #(
    .INIT ( 64'hFFEFFEEE11011000 ))
  blk00000354 (
    .I0(sig00000052),
    .I1(sig00000053),
    .I2(sig0000004f),
    .I3(sig00000039),
    .I4(sig0000001d),
    .I5(sig00000051),
    .O(sig000001ef)
  );
  MUXF7   blk00000355 (
    .I0(sig000001f0),
    .I1(sig000001f1),
    .S(sig00000054),
    .O(sig00000069)
  );
  LUT6 #(
    .INIT ( 64'hFD75B931EC64A820 ))
  blk00000356 (
    .I0(sig00000053),
    .I1(sig00000052),
    .I2(sig00000083),
    .I3(sig00000084),
    .I4(sig00000082),
    .I5(sig00000081),
    .O(sig000001f0)
  );
  LUT6 #(
    .INIT ( 64'hFEFEFE1010FE1010 ))
  blk00000357 (
    .I0(sig00000053),
    .I1(sig00000052),
    .I2(sig00000085),
    .I3(sig0000004f),
    .I4(sig0000002b),
    .I5(sig00000046),
    .O(sig000001f1)
  );
  MUXF7   blk00000358 (
    .I0(sig000001f2),
    .I1(sig000001f3),
    .S(sig00000052),
    .O(sig0000005c)
  );
  LUT6 #(
    .INIT ( 64'hFD75B931EC64A820 ))
  blk00000359 (
    .I0(sig00000053),
    .I1(sig00000054),
    .I2(sig00000075),
    .I3(sig00000079),
    .I4(sig00000077),
    .I5(sig00000073),
    .O(sig000001f2)
  );
  LUT6 #(
    .INIT ( 64'hFD75B931EC64A820 ))
  blk0000035a (
    .I0(sig00000053),
    .I1(sig00000054),
    .I2(sig00000076),
    .I3(sig000001e4),
    .I4(sig00000078),
    .I5(sig00000074),
    .O(sig000001f3)
  );
  MUXF7   blk0000035b (
    .I0(sig000001f4),
    .I1(sig000001f5),
    .S(sig00000052),
    .O(sig00000059)
  );
  LUT6 #(
    .INIT ( 64'hFD75B931EC64A820 ))
  blk0000035c (
    .I0(sig00000053),
    .I1(sig00000054),
    .I2(sig00000072),
    .I3(sig00000076),
    .I4(sig00000074),
    .I5(sig00000070),
    .O(sig000001f4)
  );
  LUT6 #(
    .INIT ( 64'hFD75B931EC64A820 ))
  blk0000035d (
    .I0(sig00000053),
    .I1(sig00000054),
    .I2(sig00000073),
    .I3(sig00000077),
    .I4(sig00000075),
    .I5(sig00000071),
    .O(sig000001f5)
  );
  MUXF7   blk0000035e (
    .I0(sig000001f6),
    .I1(sig000001f7),
    .S(sig00000052),
    .O(sig00000064)
  );
  LUT6 #(
    .INIT ( 64'hFD75B931EC64A820 ))
  blk0000035f (
    .I0(sig00000053),
    .I1(sig00000054),
    .I2(sig0000007e),
    .I3(sig00000082),
    .I4(sig00000080),
    .I5(sig0000007c),
    .O(sig000001f6)
  );
  LUT6 #(
    .INIT ( 64'hFD75B931EC64A820 ))
  blk00000360 (
    .I0(sig00000053),
    .I1(sig00000054),
    .I2(sig0000007f),
    .I3(sig00000083),
    .I4(sig00000081),
    .I5(sig0000007d),
    .O(sig000001f7)
  );
  INV   blk00000361 (
    .I(sig000000c0),
    .O(sig00000094)
  );
  INV   blk00000362 (
    .I(sig000000bf),
    .O(sig00000095)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk00000363 (
    .A0(sig000000a0),
    .A1(sig00000001),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig00000002),
    .Q(sig000001f8),
    .Q15(NLW_blk00000363_Q15_UNCONNECTED)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk00000364 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000001f8),
    .Q(sig0000014c)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk00000365 (
    .A0(sig000000a0),
    .A1(sig000000a0),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig0000002b),
    .Q(sig000001f9),
    .Q15(NLW_blk00000365_Q15_UNCONNECTED)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk00000366 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000001f9),
    .Q(sig00000173)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk00000367 (
    .A0(sig000000a0),
    .A1(sig000000a0),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig0000002a),
    .Q(sig000001fa),
    .Q15(NLW_blk00000367_Q15_UNCONNECTED)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk00000368 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000001fa),
    .Q(sig00000172)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk00000369 (
    .A0(sig000000a0),
    .A1(sig000000a0),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig00000027),
    .Q(sig000001fb),
    .Q15(NLW_blk00000369_Q15_UNCONNECTED)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk0000036a (
    .C(clk),
    .CE(sig00000001),
    .D(sig000001fb),
    .Q(sig0000016f)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk0000036b (
    .A0(sig000000a0),
    .A1(sig000000a0),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig00000029),
    .Q(sig000001fc),
    .Q15(NLW_blk0000036b_Q15_UNCONNECTED)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk0000036c (
    .C(clk),
    .CE(sig00000001),
    .D(sig000001fc),
    .Q(sig00000171)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk0000036d (
    .A0(sig000000a0),
    .A1(sig000000a0),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig00000028),
    .Q(sig000001fd),
    .Q15(NLW_blk0000036d_Q15_UNCONNECTED)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk0000036e (
    .C(clk),
    .CE(sig00000001),
    .D(sig000001fd),
    .Q(sig00000170)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk0000036f (
    .A0(sig000000a0),
    .A1(sig000000a0),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig00000024),
    .Q(sig000001fe),
    .Q15(NLW_blk0000036f_Q15_UNCONNECTED)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk00000370 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000001fe),
    .Q(sig0000016c)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk00000371 (
    .A0(sig000000a0),
    .A1(sig000000a0),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig00000026),
    .Q(sig000001ff),
    .Q15(NLW_blk00000371_Q15_UNCONNECTED)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk00000372 (
    .C(clk),
    .CE(sig00000001),
    .D(sig000001ff),
    .Q(sig0000016e)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk00000373 (
    .A0(sig000000a0),
    .A1(sig000000a0),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig00000025),
    .Q(sig00000200),
    .Q15(NLW_blk00000373_Q15_UNCONNECTED)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk00000374 (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000200),
    .Q(sig0000016d)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk00000375 (
    .A0(sig000000a0),
    .A1(sig000000a0),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig00000021),
    .Q(sig00000201),
    .Q15(NLW_blk00000375_Q15_UNCONNECTED)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk00000376 (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000201),
    .Q(sig00000169)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk00000377 (
    .A0(sig000000a0),
    .A1(sig000000a0),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig00000023),
    .Q(sig00000202),
    .Q15(NLW_blk00000377_Q15_UNCONNECTED)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk00000378 (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000202),
    .Q(sig0000016b)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk00000379 (
    .A0(sig000000a0),
    .A1(sig000000a0),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig00000022),
    .Q(sig00000203),
    .Q15(NLW_blk00000379_Q15_UNCONNECTED)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk0000037a (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000203),
    .Q(sig0000016a)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk0000037b (
    .A0(sig000000a0),
    .A1(sig00000001),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig00000157),
    .Q(sig00000141),
    .Q15(NLW_blk0000037b_Q15_UNCONNECTED)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk0000037c (
    .A0(sig000000a0),
    .A1(sig000000a0),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig00000020),
    .Q(sig00000204),
    .Q15(NLW_blk0000037c_Q15_UNCONNECTED)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk0000037d (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000204),
    .Q(sig00000168)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk0000037e (
    .A0(sig000000a0),
    .A1(sig000000a0),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig0000001f),
    .Q(sig00000205),
    .Q15(NLW_blk0000037e_Q15_UNCONNECTED)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk0000037f (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000205),
    .Q(sig00000167)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk00000380 (
    .A0(sig000000a0),
    .A1(sig00000001),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig00000154),
    .Q(sig0000013e),
    .Q15(NLW_blk00000380_Q15_UNCONNECTED)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk00000381 (
    .A0(sig000000a0),
    .A1(sig00000001),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig00000156),
    .Q(sig00000140),
    .Q15(NLW_blk00000381_Q15_UNCONNECTED)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk00000382 (
    .A0(sig000000a0),
    .A1(sig00000001),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig00000155),
    .Q(sig0000013f),
    .Q15(NLW_blk00000382_Q15_UNCONNECTED)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk00000383 (
    .A0(sig000000a0),
    .A1(sig00000001),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig00000151),
    .Q(sig0000013b),
    .Q15(NLW_blk00000383_Q15_UNCONNECTED)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk00000384 (
    .A0(sig000000a0),
    .A1(sig00000001),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig00000153),
    .Q(sig0000013d),
    .Q15(NLW_blk00000384_Q15_UNCONNECTED)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk00000385 (
    .A0(sig000000a0),
    .A1(sig00000001),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig00000152),
    .Q(sig0000013c),
    .Q15(NLW_blk00000385_Q15_UNCONNECTED)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk00000386 (
    .A0(sig000000a0),
    .A1(sig00000001),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig0000014e),
    .Q(sig00000138),
    .Q15(NLW_blk00000386_Q15_UNCONNECTED)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk00000387 (
    .A0(sig000000a0),
    .A1(sig00000001),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig00000150),
    .Q(sig0000013a),
    .Q15(NLW_blk00000387_Q15_UNCONNECTED)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk00000388 (
    .A0(sig000000a0),
    .A1(sig00000001),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig0000014f),
    .Q(sig00000139),
    .Q15(NLW_blk00000388_Q15_UNCONNECTED)
  );
  SRLC16E #(
    .INIT ( 16'h0000 ))
  blk00000389 (
    .A0(sig00000001),
    .A1(sig000000a0),
    .A2(sig000000a0),
    .A3(sig000000a0),
    .CE(sig00000001),
    .CLK(clk),
    .D(sig0000014c),
    .Q(sig00000206),
    .Q15(NLW_blk00000389_Q15_UNCONNECTED)
  );
  FDE #(
    .INIT ( 1'b0 ))
  blk0000038a (
    .C(clk),
    .CE(sig00000001),
    .D(sig00000206),
    .Q(sig00000137)
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk0000001a/blk00000045  (
    .I0(sig000000d4),
    .I1(sig000000ca),
    .O(\blk0000001a/sig0000023d )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk0000001a/blk00000044  (
    .I0(sig000000d4),
    .I1(sig000000ca),
    .O(\blk0000001a/sig00000224 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk0000001a/blk00000043  (
    .I0(sig000000d4),
    .I1(sig000000ca),
    .O(\blk0000001a/sig00000225 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk0000001a/blk00000042  (
    .I0(sig000000d3),
    .I1(sig000000c9),
    .O(\blk0000001a/sig00000226 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk0000001a/blk00000041  (
    .I0(sig000000d2),
    .I1(sig000000c8),
    .O(\blk0000001a/sig00000227 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk0000001a/blk00000040  (
    .I0(sig000000d1),
    .I1(sig000000c7),
    .O(\blk0000001a/sig00000228 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk0000001a/blk0000003f  (
    .I0(sig000000d0),
    .I1(sig000000c6),
    .O(\blk0000001a/sig00000229 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk0000001a/blk0000003e  (
    .I0(sig000000cf),
    .I1(sig000000c5),
    .O(\blk0000001a/sig0000022a )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk0000001a/blk0000003d  (
    .I0(sig000000ce),
    .I1(sig000000c4),
    .O(\blk0000001a/sig0000022b )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk0000001a/blk0000003c  (
    .I0(sig000000cd),
    .I1(sig000000c3),
    .O(\blk0000001a/sig0000022c )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk0000001a/blk0000003b  (
    .I0(sig000000cc),
    .I1(sig000000c2),
    .O(\blk0000001a/sig0000022d )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk0000001a/blk0000003a  (
    .I0(sig000000cb),
    .I1(sig000000c1),
    .O(\blk0000001a/sig0000022e )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000001a/blk00000039  (
    .C(clk),
    .D(\blk0000001a/sig00000223 ),
    .Q(sig000000c0)
  );
  MUXCY   \blk0000001a/blk00000038  (
    .CI(\blk0000001a/sig00000222 ),
    .DI(sig000000a0),
    .S(\blk0000001a/sig00000222 ),
    .O(\blk0000001a/sig0000023c )
  );
  MUXCY   \blk0000001a/blk00000037  (
    .CI(\blk0000001a/sig0000023c ),
    .DI(sig000000a0),
    .S(\blk0000001a/sig00000222 ),
    .O(\blk0000001a/sig0000023b )
  );
  MUXCY   \blk0000001a/blk00000036  (
    .CI(\blk0000001a/sig0000023b ),
    .DI(sig000000a0),
    .S(\blk0000001a/sig00000222 ),
    .O(\blk0000001a/sig0000023a )
  );
  MUXCY   \blk0000001a/blk00000035  (
    .CI(\blk0000001a/sig0000023a ),
    .DI(sig000000cb),
    .S(\blk0000001a/sig0000022e ),
    .O(\blk0000001a/sig00000239 )
  );
  MUXCY   \blk0000001a/blk00000034  (
    .CI(\blk0000001a/sig00000239 ),
    .DI(sig000000cc),
    .S(\blk0000001a/sig0000022d ),
    .O(\blk0000001a/sig00000238 )
  );
  MUXCY   \blk0000001a/blk00000033  (
    .CI(\blk0000001a/sig00000238 ),
    .DI(sig000000cd),
    .S(\blk0000001a/sig0000022c ),
    .O(\blk0000001a/sig00000237 )
  );
  MUXCY   \blk0000001a/blk00000032  (
    .CI(\blk0000001a/sig00000237 ),
    .DI(sig000000ce),
    .S(\blk0000001a/sig0000022b ),
    .O(\blk0000001a/sig00000236 )
  );
  MUXCY   \blk0000001a/blk00000031  (
    .CI(\blk0000001a/sig00000236 ),
    .DI(sig000000cf),
    .S(\blk0000001a/sig0000022a ),
    .O(\blk0000001a/sig00000235 )
  );
  MUXCY   \blk0000001a/blk00000030  (
    .CI(\blk0000001a/sig00000235 ),
    .DI(sig000000d0),
    .S(\blk0000001a/sig00000229 ),
    .O(\blk0000001a/sig00000234 )
  );
  MUXCY   \blk0000001a/blk0000002f  (
    .CI(\blk0000001a/sig00000234 ),
    .DI(sig000000d1),
    .S(\blk0000001a/sig00000228 ),
    .O(\blk0000001a/sig00000233 )
  );
  MUXCY   \blk0000001a/blk0000002e  (
    .CI(\blk0000001a/sig00000233 ),
    .DI(sig000000d2),
    .S(\blk0000001a/sig00000227 ),
    .O(\blk0000001a/sig00000232 )
  );
  MUXCY   \blk0000001a/blk0000002d  (
    .CI(\blk0000001a/sig00000232 ),
    .DI(sig000000d3),
    .S(\blk0000001a/sig00000226 ),
    .O(\blk0000001a/sig00000231 )
  );
  MUXCY   \blk0000001a/blk0000002c  (
    .CI(\blk0000001a/sig00000231 ),
    .DI(sig000000d4),
    .S(\blk0000001a/sig00000225 ),
    .O(\blk0000001a/sig00000230 )
  );
  MUXCY   \blk0000001a/blk0000002b  (
    .CI(\blk0000001a/sig00000230 ),
    .DI(sig000000d4),
    .S(\blk0000001a/sig0000023d ),
    .O(\blk0000001a/sig0000022f )
  );
  XORCY   \blk0000001a/blk0000002a  (
    .CI(\blk0000001a/sig0000023c ),
    .LI(\blk0000001a/sig00000222 ),
    .O(\NLW_blk0000001a/blk0000002a_O_UNCONNECTED )
  );
  XORCY   \blk0000001a/blk00000029  (
    .CI(\blk0000001a/sig0000023b ),
    .LI(\blk0000001a/sig00000222 ),
    .O(\NLW_blk0000001a/blk00000029_O_UNCONNECTED )
  );
  XORCY   \blk0000001a/blk00000028  (
    .CI(\blk0000001a/sig0000023a ),
    .LI(\blk0000001a/sig0000022e ),
    .O(\NLW_blk0000001a/blk00000028_O_UNCONNECTED )
  );
  XORCY   \blk0000001a/blk00000027  (
    .CI(\blk0000001a/sig00000239 ),
    .LI(\blk0000001a/sig0000022d ),
    .O(\NLW_blk0000001a/blk00000027_O_UNCONNECTED )
  );
  XORCY   \blk0000001a/blk00000026  (
    .CI(\blk0000001a/sig00000238 ),
    .LI(\blk0000001a/sig0000022c ),
    .O(\NLW_blk0000001a/blk00000026_O_UNCONNECTED )
  );
  XORCY   \blk0000001a/blk00000025  (
    .CI(\blk0000001a/sig00000237 ),
    .LI(\blk0000001a/sig0000022b ),
    .O(\NLW_blk0000001a/blk00000025_O_UNCONNECTED )
  );
  XORCY   \blk0000001a/blk00000024  (
    .CI(\blk0000001a/sig00000236 ),
    .LI(\blk0000001a/sig0000022a ),
    .O(\NLW_blk0000001a/blk00000024_O_UNCONNECTED )
  );
  XORCY   \blk0000001a/blk00000023  (
    .CI(\blk0000001a/sig00000235 ),
    .LI(\blk0000001a/sig00000229 ),
    .O(\NLW_blk0000001a/blk00000023_O_UNCONNECTED )
  );
  XORCY   \blk0000001a/blk00000022  (
    .CI(\blk0000001a/sig00000234 ),
    .LI(\blk0000001a/sig00000228 ),
    .O(\NLW_blk0000001a/blk00000022_O_UNCONNECTED )
  );
  XORCY   \blk0000001a/blk00000021  (
    .CI(\blk0000001a/sig00000233 ),
    .LI(\blk0000001a/sig00000227 ),
    .O(\NLW_blk0000001a/blk00000021_O_UNCONNECTED )
  );
  XORCY   \blk0000001a/blk00000020  (
    .CI(\blk0000001a/sig00000232 ),
    .LI(\blk0000001a/sig00000226 ),
    .O(\NLW_blk0000001a/blk00000020_O_UNCONNECTED )
  );
  XORCY   \blk0000001a/blk0000001f  (
    .CI(\blk0000001a/sig00000231 ),
    .LI(\blk0000001a/sig00000225 ),
    .O(\NLW_blk0000001a/blk0000001f_O_UNCONNECTED )
  );
  XORCY   \blk0000001a/blk0000001e  (
    .CI(\blk0000001a/sig00000230 ),
    .LI(\blk0000001a/sig0000023d ),
    .O(\blk0000001a/sig00000223 )
  );
  XORCY   \blk0000001a/blk0000001d  (
    .CI(\blk0000001a/sig0000022f ),
    .LI(\blk0000001a/sig00000224 ),
    .O(\NLW_blk0000001a/blk0000001d_O_UNCONNECTED )
  );
  XORCY   \blk0000001a/blk0000001c  (
    .CI(\blk0000001a/sig00000222 ),
    .LI(\blk0000001a/sig00000222 ),
    .O(\NLW_blk0000001a/blk0000001c_O_UNCONNECTED )
  );
  VCC   \blk0000001a/blk0000001b  (
    .P(\blk0000001a/sig00000222 )
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  \blk00000046/blk00000071  (
    .I0(sig000000d4),
    .I1(sig000000ca),
    .O(\blk00000046/sig00000274 )
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  \blk00000046/blk00000070  (
    .I0(sig000000d4),
    .I1(sig000000ca),
    .O(\blk00000046/sig0000025b )
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  \blk00000046/blk0000006f  (
    .I0(sig000000d4),
    .I1(sig000000ca),
    .O(\blk00000046/sig0000025c )
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  \blk00000046/blk0000006e  (
    .I0(sig000000d3),
    .I1(sig000000c9),
    .O(\blk00000046/sig0000025d )
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  \blk00000046/blk0000006d  (
    .I0(sig000000d2),
    .I1(sig000000c8),
    .O(\blk00000046/sig0000025e )
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  \blk00000046/blk0000006c  (
    .I0(sig000000d1),
    .I1(sig000000c7),
    .O(\blk00000046/sig0000025f )
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  \blk00000046/blk0000006b  (
    .I0(sig000000d0),
    .I1(sig000000c6),
    .O(\blk00000046/sig00000260 )
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  \blk00000046/blk0000006a  (
    .I0(sig000000cf),
    .I1(sig000000c5),
    .O(\blk00000046/sig00000261 )
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  \blk00000046/blk00000069  (
    .I0(sig000000ce),
    .I1(sig000000c4),
    .O(\blk00000046/sig00000262 )
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  \blk00000046/blk00000068  (
    .I0(sig000000cd),
    .I1(sig000000c3),
    .O(\blk00000046/sig00000263 )
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  \blk00000046/blk00000067  (
    .I0(sig000000cc),
    .I1(sig000000c2),
    .O(\blk00000046/sig00000264 )
  );
  LUT2 #(
    .INIT ( 4'h6 ))
  \blk00000046/blk00000066  (
    .I0(sig000000cb),
    .I1(sig000000c1),
    .O(\blk00000046/sig00000265 )
  );
  MUXCY   \blk00000046/blk00000065  (
    .CI(\blk00000046/sig00000259 ),
    .DI(sig000000a0),
    .S(\blk00000046/sig00000259 ),
    .O(\blk00000046/sig00000273 )
  );
  MUXCY   \blk00000046/blk00000064  (
    .CI(\blk00000046/sig00000273 ),
    .DI(sig000000a0),
    .S(\blk00000046/sig00000259 ),
    .O(\blk00000046/sig00000272 )
  );
  MUXCY   \blk00000046/blk00000063  (
    .CI(\blk00000046/sig00000272 ),
    .DI(sig000000a0),
    .S(\blk00000046/sig00000259 ),
    .O(\blk00000046/sig00000271 )
  );
  MUXCY   \blk00000046/blk00000062  (
    .CI(\blk00000046/sig00000271 ),
    .DI(sig000000cb),
    .S(\blk00000046/sig00000265 ),
    .O(\blk00000046/sig00000270 )
  );
  MUXCY   \blk00000046/blk00000061  (
    .CI(\blk00000046/sig00000270 ),
    .DI(sig000000cc),
    .S(\blk00000046/sig00000264 ),
    .O(\blk00000046/sig0000026f )
  );
  MUXCY   \blk00000046/blk00000060  (
    .CI(\blk00000046/sig0000026f ),
    .DI(sig000000cd),
    .S(\blk00000046/sig00000263 ),
    .O(\blk00000046/sig0000026e )
  );
  MUXCY   \blk00000046/blk0000005f  (
    .CI(\blk00000046/sig0000026e ),
    .DI(sig000000ce),
    .S(\blk00000046/sig00000262 ),
    .O(\blk00000046/sig0000026d )
  );
  MUXCY   \blk00000046/blk0000005e  (
    .CI(\blk00000046/sig0000026d ),
    .DI(sig000000cf),
    .S(\blk00000046/sig00000261 ),
    .O(\blk00000046/sig0000026c )
  );
  MUXCY   \blk00000046/blk0000005d  (
    .CI(\blk00000046/sig0000026c ),
    .DI(sig000000d0),
    .S(\blk00000046/sig00000260 ),
    .O(\blk00000046/sig0000026b )
  );
  MUXCY   \blk00000046/blk0000005c  (
    .CI(\blk00000046/sig0000026b ),
    .DI(sig000000d1),
    .S(\blk00000046/sig0000025f ),
    .O(\blk00000046/sig0000026a )
  );
  MUXCY   \blk00000046/blk0000005b  (
    .CI(\blk00000046/sig0000026a ),
    .DI(sig000000d2),
    .S(\blk00000046/sig0000025e ),
    .O(\blk00000046/sig00000269 )
  );
  MUXCY   \blk00000046/blk0000005a  (
    .CI(\blk00000046/sig00000269 ),
    .DI(sig000000d3),
    .S(\blk00000046/sig0000025d ),
    .O(\blk00000046/sig00000268 )
  );
  MUXCY   \blk00000046/blk00000059  (
    .CI(\blk00000046/sig00000268 ),
    .DI(sig000000d4),
    .S(\blk00000046/sig0000025c ),
    .O(\blk00000046/sig00000267 )
  );
  MUXCY   \blk00000046/blk00000058  (
    .CI(\blk00000046/sig00000267 ),
    .DI(sig000000d4),
    .S(\blk00000046/sig00000274 ),
    .O(\blk00000046/sig00000266 )
  );
  XORCY   \blk00000046/blk00000057  (
    .CI(\blk00000046/sig00000273 ),
    .LI(\blk00000046/sig00000259 ),
    .O(\NLW_blk00000046/blk00000057_O_UNCONNECTED )
  );
  XORCY   \blk00000046/blk00000056  (
    .CI(\blk00000046/sig00000272 ),
    .LI(\blk00000046/sig00000259 ),
    .O(\NLW_blk00000046/blk00000056_O_UNCONNECTED )
  );
  XORCY   \blk00000046/blk00000055  (
    .CI(\blk00000046/sig00000271 ),
    .LI(\blk00000046/sig00000265 ),
    .O(\NLW_blk00000046/blk00000055_O_UNCONNECTED )
  );
  XORCY   \blk00000046/blk00000054  (
    .CI(\blk00000046/sig00000270 ),
    .LI(\blk00000046/sig00000264 ),
    .O(\NLW_blk00000046/blk00000054_O_UNCONNECTED )
  );
  XORCY   \blk00000046/blk00000053  (
    .CI(\blk00000046/sig0000026f ),
    .LI(\blk00000046/sig00000263 ),
    .O(\NLW_blk00000046/blk00000053_O_UNCONNECTED )
  );
  XORCY   \blk00000046/blk00000052  (
    .CI(\blk00000046/sig0000026e ),
    .LI(\blk00000046/sig00000262 ),
    .O(\NLW_blk00000046/blk00000052_O_UNCONNECTED )
  );
  XORCY   \blk00000046/blk00000051  (
    .CI(\blk00000046/sig0000026d ),
    .LI(\blk00000046/sig00000261 ),
    .O(\NLW_blk00000046/blk00000051_O_UNCONNECTED )
  );
  XORCY   \blk00000046/blk00000050  (
    .CI(\blk00000046/sig0000026c ),
    .LI(\blk00000046/sig00000260 ),
    .O(\NLW_blk00000046/blk00000050_O_UNCONNECTED )
  );
  XORCY   \blk00000046/blk0000004f  (
    .CI(\blk00000046/sig0000026b ),
    .LI(\blk00000046/sig0000025f ),
    .O(\NLW_blk00000046/blk0000004f_O_UNCONNECTED )
  );
  XORCY   \blk00000046/blk0000004e  (
    .CI(\blk00000046/sig0000026a ),
    .LI(\blk00000046/sig0000025e ),
    .O(\NLW_blk00000046/blk0000004e_O_UNCONNECTED )
  );
  XORCY   \blk00000046/blk0000004d  (
    .CI(\blk00000046/sig00000269 ),
    .LI(\blk00000046/sig0000025d ),
    .O(\NLW_blk00000046/blk0000004d_O_UNCONNECTED )
  );
  XORCY   \blk00000046/blk0000004c  (
    .CI(\blk00000046/sig00000268 ),
    .LI(\blk00000046/sig0000025c ),
    .O(\NLW_blk00000046/blk0000004c_O_UNCONNECTED )
  );
  XORCY   \blk00000046/blk0000004b  (
    .CI(\blk00000046/sig00000267 ),
    .LI(\blk00000046/sig00000274 ),
    .O(\blk00000046/sig0000025a )
  );
  XORCY   \blk00000046/blk0000004a  (
    .CI(\blk00000046/sig00000266 ),
    .LI(\blk00000046/sig0000025b ),
    .O(\NLW_blk00000046/blk0000004a_O_UNCONNECTED )
  );
  XORCY   \blk00000046/blk00000049  (
    .CI(\blk00000046/sig00000259 ),
    .LI(\blk00000046/sig00000259 ),
    .O(\NLW_blk00000046/blk00000049_O_UNCONNECTED )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000046/blk00000048  (
    .C(clk),
    .D(\blk00000046/sig0000025a ),
    .Q(sig000000bf)
  );
  GND   \blk00000046/blk00000047  (
    .G(\blk00000046/sig00000259 )
  );
  INV   \blk00000086/blk000000bc  (
    .I(sig00000095),
    .O(\blk00000086/sig000002c0 )
  );
  INV   \blk00000086/blk000000bb  (
    .I(sig00000095),
    .O(\blk00000086/sig000002b0 )
  );
  INV   \blk00000086/blk000000ba  (
    .I(sig00000095),
    .O(\blk00000086/sig000002b1 )
  );
  INV   \blk00000086/blk000000b9  (
    .I(sig00000095),
    .O(\blk00000086/sig000002b2 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk00000086/blk000000b8  (
    .I0(sig000000aa),
    .I1(sig00000095),
    .O(\blk00000086/sig000002c1 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk00000086/blk000000b7  (
    .I0(sig000000a7),
    .I1(sig00000095),
    .O(\blk00000086/sig000002a9 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk00000086/blk000000b6  (
    .I0(sig000000a6),
    .I1(sig00000095),
    .O(\blk00000086/sig000002aa )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk00000086/blk000000b5  (
    .I0(sig000000a5),
    .I1(sig00000095),
    .O(\blk00000086/sig000002ab )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk00000086/blk000000b4  (
    .I0(sig000000a4),
    .I1(sig00000095),
    .O(\blk00000086/sig000002ac )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk00000086/blk000000b3  (
    .I0(sig000000a3),
    .I1(sig00000095),
    .O(\blk00000086/sig000002ad )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk00000086/blk000000b2  (
    .I0(sig000000a2),
    .I1(sig00000095),
    .O(\blk00000086/sig000002ae )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk00000086/blk000000b1  (
    .I0(sig000000a1),
    .I1(sig00000095),
    .O(\blk00000086/sig000002af )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk00000086/blk000000b0  (
    .I0(sig000000aa),
    .I1(sig00000095),
    .O(\blk00000086/sig000002a6 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk00000086/blk000000af  (
    .I0(sig000000a9),
    .I1(sig00000095),
    .O(\blk00000086/sig000002a7 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk00000086/blk000000ae  (
    .I0(sig000000a8),
    .I1(sig00000095),
    .O(\blk00000086/sig000002a8 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000086/blk000000ad  (
    .C(clk),
    .D(\blk00000086/sig000002a5 ),
    .Q(sig0000003b)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000086/blk000000ac  (
    .C(clk),
    .D(\blk00000086/sig000002a4 ),
    .Q(sig0000003c)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000086/blk000000ab  (
    .C(clk),
    .D(\blk00000086/sig000002a3 ),
    .Q(sig0000003d)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000086/blk000000aa  (
    .C(clk),
    .D(\blk00000086/sig000002a2 ),
    .Q(sig0000003e)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000086/blk000000a9  (
    .C(clk),
    .D(\blk00000086/sig000002a1 ),
    .Q(sig0000003f)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000086/blk000000a8  (
    .C(clk),
    .D(\blk00000086/sig000002a0 ),
    .Q(sig00000040)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000086/blk000000a7  (
    .C(clk),
    .D(\blk00000086/sig0000029f ),
    .Q(sig00000041)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000086/blk000000a6  (
    .C(clk),
    .D(\blk00000086/sig0000029e ),
    .Q(sig00000042)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000086/blk000000a5  (
    .C(clk),
    .D(\blk00000086/sig0000029d ),
    .Q(sig00000043)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000086/blk000000a4  (
    .C(clk),
    .D(\blk00000086/sig0000029c ),
    .Q(sig00000044)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000086/blk000000a3  (
    .C(clk),
    .D(\blk00000086/sig0000029b ),
    .Q(sig00000045)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000086/blk000000a2  (
    .C(clk),
    .D(\blk00000086/sig0000029a ),
    .Q(sig00000046)
  );
  MUXCY   \blk00000086/blk000000a1  (
    .CI(\blk00000086/sig000002c0 ),
    .DI(sig000000a0),
    .S(\blk00000086/sig000002b2 ),
    .O(\blk00000086/sig000002bf )
  );
  MUXCY   \blk00000086/blk000000a0  (
    .CI(\blk00000086/sig000002bf ),
    .DI(sig000000a0),
    .S(\blk00000086/sig000002b1 ),
    .O(\blk00000086/sig000002be )
  );
  MUXCY   \blk00000086/blk0000009f  (
    .CI(\blk00000086/sig000002be ),
    .DI(sig000000a0),
    .S(\blk00000086/sig000002b0 ),
    .O(\blk00000086/sig000002bd )
  );
  MUXCY   \blk00000086/blk0000009e  (
    .CI(\blk00000086/sig000002bd ),
    .DI(sig000000a0),
    .S(\blk00000086/sig000002af ),
    .O(\blk00000086/sig000002bc )
  );
  MUXCY   \blk00000086/blk0000009d  (
    .CI(\blk00000086/sig000002bc ),
    .DI(sig000000a0),
    .S(\blk00000086/sig000002ae ),
    .O(\blk00000086/sig000002bb )
  );
  MUXCY   \blk00000086/blk0000009c  (
    .CI(\blk00000086/sig000002bb ),
    .DI(sig000000a0),
    .S(\blk00000086/sig000002ad ),
    .O(\blk00000086/sig000002ba )
  );
  MUXCY   \blk00000086/blk0000009b  (
    .CI(\blk00000086/sig000002ba ),
    .DI(sig000000a0),
    .S(\blk00000086/sig000002ac ),
    .O(\blk00000086/sig000002b9 )
  );
  MUXCY   \blk00000086/blk0000009a  (
    .CI(\blk00000086/sig000002b9 ),
    .DI(sig000000a0),
    .S(\blk00000086/sig000002ab ),
    .O(\blk00000086/sig000002b8 )
  );
  MUXCY   \blk00000086/blk00000099  (
    .CI(\blk00000086/sig000002b8 ),
    .DI(sig000000a0),
    .S(\blk00000086/sig000002aa ),
    .O(\blk00000086/sig000002b7 )
  );
  MUXCY   \blk00000086/blk00000098  (
    .CI(\blk00000086/sig000002b7 ),
    .DI(sig000000a0),
    .S(\blk00000086/sig000002a9 ),
    .O(\blk00000086/sig000002b6 )
  );
  MUXCY   \blk00000086/blk00000097  (
    .CI(\blk00000086/sig000002b6 ),
    .DI(sig000000a0),
    .S(\blk00000086/sig000002a8 ),
    .O(\blk00000086/sig000002b5 )
  );
  MUXCY   \blk00000086/blk00000096  (
    .CI(\blk00000086/sig000002b5 ),
    .DI(sig000000a0),
    .S(\blk00000086/sig000002a7 ),
    .O(\blk00000086/sig000002b4 )
  );
  MUXCY   \blk00000086/blk00000095  (
    .CI(\blk00000086/sig000002b4 ),
    .DI(sig000000a0),
    .S(\blk00000086/sig000002c1 ),
    .O(\blk00000086/sig000002b3 )
  );
  XORCY   \blk00000086/blk00000094  (
    .CI(\blk00000086/sig000002c0 ),
    .LI(\blk00000086/sig000002b2 ),
    .O(\NLW_blk00000086/blk00000094_O_UNCONNECTED )
  );
  XORCY   \blk00000086/blk00000093  (
    .CI(\blk00000086/sig000002bf ),
    .LI(\blk00000086/sig000002b1 ),
    .O(\blk00000086/sig000002a5 )
  );
  XORCY   \blk00000086/blk00000092  (
    .CI(\blk00000086/sig000002be ),
    .LI(\blk00000086/sig000002b0 ),
    .O(\blk00000086/sig000002a4 )
  );
  XORCY   \blk00000086/blk00000091  (
    .CI(\blk00000086/sig000002bd ),
    .LI(\blk00000086/sig000002af ),
    .O(\blk00000086/sig000002a3 )
  );
  XORCY   \blk00000086/blk00000090  (
    .CI(\blk00000086/sig000002bc ),
    .LI(\blk00000086/sig000002ae ),
    .O(\blk00000086/sig000002a2 )
  );
  XORCY   \blk00000086/blk0000008f  (
    .CI(\blk00000086/sig000002bb ),
    .LI(\blk00000086/sig000002ad ),
    .O(\blk00000086/sig000002a1 )
  );
  XORCY   \blk00000086/blk0000008e  (
    .CI(\blk00000086/sig000002ba ),
    .LI(\blk00000086/sig000002ac ),
    .O(\blk00000086/sig000002a0 )
  );
  XORCY   \blk00000086/blk0000008d  (
    .CI(\blk00000086/sig000002b9 ),
    .LI(\blk00000086/sig000002ab ),
    .O(\blk00000086/sig0000029f )
  );
  XORCY   \blk00000086/blk0000008c  (
    .CI(\blk00000086/sig000002b8 ),
    .LI(\blk00000086/sig000002aa ),
    .O(\blk00000086/sig0000029e )
  );
  XORCY   \blk00000086/blk0000008b  (
    .CI(\blk00000086/sig000002b7 ),
    .LI(\blk00000086/sig000002a9 ),
    .O(\blk00000086/sig0000029d )
  );
  XORCY   \blk00000086/blk0000008a  (
    .CI(\blk00000086/sig000002b6 ),
    .LI(\blk00000086/sig000002a8 ),
    .O(\blk00000086/sig0000029c )
  );
  XORCY   \blk00000086/blk00000089  (
    .CI(\blk00000086/sig000002b5 ),
    .LI(\blk00000086/sig000002a7 ),
    .O(\blk00000086/sig0000029b )
  );
  XORCY   \blk00000086/blk00000088  (
    .CI(\blk00000086/sig000002b4 ),
    .LI(\blk00000086/sig000002c1 ),
    .O(\blk00000086/sig0000029a )
  );
  XORCY   \blk00000086/blk00000087  (
    .CI(\blk00000086/sig000002b3 ),
    .LI(\blk00000086/sig000002a6 ),
    .O(\NLW_blk00000086/blk00000087_O_UNCONNECTED )
  );
  INV   \blk000000bd/blk000000f3  (
    .I(sig00000094),
    .O(\blk000000bd/sig0000030d )
  );
  INV   \blk000000bd/blk000000f2  (
    .I(sig00000094),
    .O(\blk000000bd/sig000002fd )
  );
  INV   \blk000000bd/blk000000f1  (
    .I(sig00000094),
    .O(\blk000000bd/sig000002fe )
  );
  INV   \blk000000bd/blk000000f0  (
    .I(sig00000094),
    .O(\blk000000bd/sig000002ff )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000000bd/blk000000ef  (
    .I0(sig0000009f),
    .I1(sig00000094),
    .O(\blk000000bd/sig0000030e )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000000bd/blk000000ee  (
    .I0(sig0000009c),
    .I1(sig00000094),
    .O(\blk000000bd/sig000002f6 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000000bd/blk000000ed  (
    .I0(sig0000009b),
    .I1(sig00000094),
    .O(\blk000000bd/sig000002f7 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000000bd/blk000000ec  (
    .I0(sig0000009a),
    .I1(sig00000094),
    .O(\blk000000bd/sig000002f8 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000000bd/blk000000eb  (
    .I0(sig00000099),
    .I1(sig00000094),
    .O(\blk000000bd/sig000002f9 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000000bd/blk000000ea  (
    .I0(sig00000098),
    .I1(sig00000094),
    .O(\blk000000bd/sig000002fa )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000000bd/blk000000e9  (
    .I0(sig00000097),
    .I1(sig00000094),
    .O(\blk000000bd/sig000002fb )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000000bd/blk000000e8  (
    .I0(sig00000096),
    .I1(sig00000094),
    .O(\blk000000bd/sig000002fc )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000000bd/blk000000e7  (
    .I0(sig0000009f),
    .I1(sig00000094),
    .O(\blk000000bd/sig000002f3 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000000bd/blk000000e6  (
    .I0(sig0000009e),
    .I1(sig00000094),
    .O(\blk000000bd/sig000002f4 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000000bd/blk000000e5  (
    .I0(sig0000009d),
    .I1(sig00000094),
    .O(\blk000000bd/sig000002f5 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000bd/blk000000e4  (
    .C(clk),
    .D(\blk000000bd/sig000002f2 ),
    .Q(sig0000002f)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000bd/blk000000e3  (
    .C(clk),
    .D(\blk000000bd/sig000002f1 ),
    .Q(sig00000030)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000bd/blk000000e2  (
    .C(clk),
    .D(\blk000000bd/sig000002f0 ),
    .Q(sig00000031)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000bd/blk000000e1  (
    .C(clk),
    .D(\blk000000bd/sig000002ef ),
    .Q(sig00000032)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000bd/blk000000e0  (
    .C(clk),
    .D(\blk000000bd/sig000002ee ),
    .Q(sig00000033)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000bd/blk000000df  (
    .C(clk),
    .D(\blk000000bd/sig000002ed ),
    .Q(sig00000034)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000bd/blk000000de  (
    .C(clk),
    .D(\blk000000bd/sig000002ec ),
    .Q(sig00000035)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000bd/blk000000dd  (
    .C(clk),
    .D(\blk000000bd/sig000002eb ),
    .Q(sig00000036)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000bd/blk000000dc  (
    .C(clk),
    .D(\blk000000bd/sig000002ea ),
    .Q(sig00000037)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000bd/blk000000db  (
    .C(clk),
    .D(\blk000000bd/sig000002e9 ),
    .Q(sig00000038)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000bd/blk000000da  (
    .C(clk),
    .D(\blk000000bd/sig000002e8 ),
    .Q(sig00000039)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000bd/blk000000d9  (
    .C(clk),
    .D(\blk000000bd/sig000002e7 ),
    .Q(sig0000003a)
  );
  MUXCY   \blk000000bd/blk000000d8  (
    .CI(\blk000000bd/sig0000030d ),
    .DI(sig000000a0),
    .S(\blk000000bd/sig000002ff ),
    .O(\blk000000bd/sig0000030c )
  );
  MUXCY   \blk000000bd/blk000000d7  (
    .CI(\blk000000bd/sig0000030c ),
    .DI(sig000000a0),
    .S(\blk000000bd/sig000002fe ),
    .O(\blk000000bd/sig0000030b )
  );
  MUXCY   \blk000000bd/blk000000d6  (
    .CI(\blk000000bd/sig0000030b ),
    .DI(sig000000a0),
    .S(\blk000000bd/sig000002fd ),
    .O(\blk000000bd/sig0000030a )
  );
  MUXCY   \blk000000bd/blk000000d5  (
    .CI(\blk000000bd/sig0000030a ),
    .DI(sig000000a0),
    .S(\blk000000bd/sig000002fc ),
    .O(\blk000000bd/sig00000309 )
  );
  MUXCY   \blk000000bd/blk000000d4  (
    .CI(\blk000000bd/sig00000309 ),
    .DI(sig000000a0),
    .S(\blk000000bd/sig000002fb ),
    .O(\blk000000bd/sig00000308 )
  );
  MUXCY   \blk000000bd/blk000000d3  (
    .CI(\blk000000bd/sig00000308 ),
    .DI(sig000000a0),
    .S(\blk000000bd/sig000002fa ),
    .O(\blk000000bd/sig00000307 )
  );
  MUXCY   \blk000000bd/blk000000d2  (
    .CI(\blk000000bd/sig00000307 ),
    .DI(sig000000a0),
    .S(\blk000000bd/sig000002f9 ),
    .O(\blk000000bd/sig00000306 )
  );
  MUXCY   \blk000000bd/blk000000d1  (
    .CI(\blk000000bd/sig00000306 ),
    .DI(sig000000a0),
    .S(\blk000000bd/sig000002f8 ),
    .O(\blk000000bd/sig00000305 )
  );
  MUXCY   \blk000000bd/blk000000d0  (
    .CI(\blk000000bd/sig00000305 ),
    .DI(sig000000a0),
    .S(\blk000000bd/sig000002f7 ),
    .O(\blk000000bd/sig00000304 )
  );
  MUXCY   \blk000000bd/blk000000cf  (
    .CI(\blk000000bd/sig00000304 ),
    .DI(sig000000a0),
    .S(\blk000000bd/sig000002f6 ),
    .O(\blk000000bd/sig00000303 )
  );
  MUXCY   \blk000000bd/blk000000ce  (
    .CI(\blk000000bd/sig00000303 ),
    .DI(sig000000a0),
    .S(\blk000000bd/sig000002f5 ),
    .O(\blk000000bd/sig00000302 )
  );
  MUXCY   \blk000000bd/blk000000cd  (
    .CI(\blk000000bd/sig00000302 ),
    .DI(sig000000a0),
    .S(\blk000000bd/sig000002f4 ),
    .O(\blk000000bd/sig00000301 )
  );
  MUXCY   \blk000000bd/blk000000cc  (
    .CI(\blk000000bd/sig00000301 ),
    .DI(sig000000a0),
    .S(\blk000000bd/sig0000030e ),
    .O(\blk000000bd/sig00000300 )
  );
  XORCY   \blk000000bd/blk000000cb  (
    .CI(\blk000000bd/sig0000030d ),
    .LI(\blk000000bd/sig000002ff ),
    .O(\NLW_blk000000bd/blk000000cb_O_UNCONNECTED )
  );
  XORCY   \blk000000bd/blk000000ca  (
    .CI(\blk000000bd/sig0000030c ),
    .LI(\blk000000bd/sig000002fe ),
    .O(\blk000000bd/sig000002f2 )
  );
  XORCY   \blk000000bd/blk000000c9  (
    .CI(\blk000000bd/sig0000030b ),
    .LI(\blk000000bd/sig000002fd ),
    .O(\blk000000bd/sig000002f1 )
  );
  XORCY   \blk000000bd/blk000000c8  (
    .CI(\blk000000bd/sig0000030a ),
    .LI(\blk000000bd/sig000002fc ),
    .O(\blk000000bd/sig000002f0 )
  );
  XORCY   \blk000000bd/blk000000c7  (
    .CI(\blk000000bd/sig00000309 ),
    .LI(\blk000000bd/sig000002fb ),
    .O(\blk000000bd/sig000002ef )
  );
  XORCY   \blk000000bd/blk000000c6  (
    .CI(\blk000000bd/sig00000308 ),
    .LI(\blk000000bd/sig000002fa ),
    .O(\blk000000bd/sig000002ee )
  );
  XORCY   \blk000000bd/blk000000c5  (
    .CI(\blk000000bd/sig00000307 ),
    .LI(\blk000000bd/sig000002f9 ),
    .O(\blk000000bd/sig000002ed )
  );
  XORCY   \blk000000bd/blk000000c4  (
    .CI(\blk000000bd/sig00000306 ),
    .LI(\blk000000bd/sig000002f8 ),
    .O(\blk000000bd/sig000002ec )
  );
  XORCY   \blk000000bd/blk000000c3  (
    .CI(\blk000000bd/sig00000305 ),
    .LI(\blk000000bd/sig000002f7 ),
    .O(\blk000000bd/sig000002eb )
  );
  XORCY   \blk000000bd/blk000000c2  (
    .CI(\blk000000bd/sig00000304 ),
    .LI(\blk000000bd/sig000002f6 ),
    .O(\blk000000bd/sig000002ea )
  );
  XORCY   \blk000000bd/blk000000c1  (
    .CI(\blk000000bd/sig00000303 ),
    .LI(\blk000000bd/sig000002f5 ),
    .O(\blk000000bd/sig000002e9 )
  );
  XORCY   \blk000000bd/blk000000c0  (
    .CI(\blk000000bd/sig00000302 ),
    .LI(\blk000000bd/sig000002f4 ),
    .O(\blk000000bd/sig000002e8 )
  );
  XORCY   \blk000000bd/blk000000bf  (
    .CI(\blk000000bd/sig00000301 ),
    .LI(\blk000000bd/sig0000030e ),
    .O(\blk000000bd/sig000002e7 )
  );
  XORCY   \blk000000bd/blk000000be  (
    .CI(\blk000000bd/sig00000300 ),
    .LI(\blk000000bd/sig000002f3 ),
    .O(\NLW_blk000000bd/blk000000be_O_UNCONNECTED )
  );
  INV   \blk000000f4/blk0000012b  (
    .I(sig00000050),
    .O(\blk000000f4/sig0000035a )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000000f4/blk0000012a  (
    .I0(sig00000093),
    .I1(sig00000050),
    .O(\blk000000f4/sig0000035b )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000000f4/blk00000129  (
    .I0(sig00000090),
    .I1(sig00000050),
    .O(\blk000000f4/sig00000343 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000000f4/blk00000128  (
    .I0(sig0000008f),
    .I1(sig00000050),
    .O(\blk000000f4/sig00000344 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk000000f4/blk00000127  (
    .I0(sig0000008e),
    .I1(sig0000004e),
    .I2(sig00000050),
    .O(\blk000000f4/sig00000345 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk000000f4/blk00000126  (
    .I0(sig0000008d),
    .I1(sig0000004d),
    .I2(sig00000050),
    .O(\blk000000f4/sig00000346 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk000000f4/blk00000125  (
    .I0(sig0000008c),
    .I1(sig0000004c),
    .I2(sig00000050),
    .O(\blk000000f4/sig00000347 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk000000f4/blk00000124  (
    .I0(sig0000008b),
    .I1(sig0000004b),
    .I2(sig00000050),
    .O(\blk000000f4/sig00000348 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk000000f4/blk00000123  (
    .I0(sig0000008a),
    .I1(sig0000004a),
    .I2(sig00000050),
    .O(\blk000000f4/sig00000349 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk000000f4/blk00000122  (
    .I0(sig00000089),
    .I1(sig00000049),
    .I2(sig00000050),
    .O(\blk000000f4/sig0000034a )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk000000f4/blk00000121  (
    .I0(sig00000088),
    .I1(sig00000048),
    .I2(sig00000050),
    .O(\blk000000f4/sig0000034b )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000000f4/blk00000120  (
    .I0(sig00000093),
    .I1(sig00000050),
    .O(\blk000000f4/sig00000340 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000000f4/blk0000011f  (
    .I0(sig00000092),
    .I1(sig00000050),
    .O(\blk000000f4/sig00000341 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000000f4/blk0000011e  (
    .I0(sig00000091),
    .I1(sig00000050),
    .O(\blk000000f4/sig00000342 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk000000f4/blk0000011d  (
    .I0(sig00000087),
    .I1(sig00000047),
    .I2(sig00000050),
    .O(\blk000000f4/sig0000034c )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000f4/blk0000011c  (
    .C(clk),
    .D(\blk000000f4/sig0000033f ),
    .Q(sig00000005)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000f4/blk0000011b  (
    .C(clk),
    .D(\blk000000f4/sig0000033e ),
    .Q(sig00000006)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000f4/blk0000011a  (
    .C(clk),
    .D(\blk000000f4/sig0000033d ),
    .Q(sig00000007)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000f4/blk00000119  (
    .C(clk),
    .D(\blk000000f4/sig0000033c ),
    .Q(sig00000008)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000f4/blk00000118  (
    .C(clk),
    .D(\blk000000f4/sig0000033b ),
    .Q(sig00000009)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000f4/blk00000117  (
    .C(clk),
    .D(\blk000000f4/sig0000033a ),
    .Q(sig0000000a)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000f4/blk00000116  (
    .C(clk),
    .D(\blk000000f4/sig00000339 ),
    .Q(sig0000000b)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000f4/blk00000115  (
    .C(clk),
    .D(\blk000000f4/sig00000338 ),
    .Q(sig0000000c)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000f4/blk00000114  (
    .C(clk),
    .D(\blk000000f4/sig00000337 ),
    .Q(sig0000000d)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000f4/blk00000113  (
    .C(clk),
    .D(\blk000000f4/sig00000336 ),
    .Q(sig0000000e)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000f4/blk00000112  (
    .C(clk),
    .D(\blk000000f4/sig00000335 ),
    .Q(sig0000000f)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000f4/blk00000111  (
    .C(clk),
    .D(\blk000000f4/sig00000334 ),
    .Q(sig00000010)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000000f4/blk00000110  (
    .C(clk),
    .D(\blk000000f4/sig00000333 ),
    .Q(sig00000011)
  );
  MUXCY   \blk000000f4/blk0000010f  (
    .CI(\blk000000f4/sig0000035a ),
    .DI(sig00000087),
    .S(\blk000000f4/sig0000034c ),
    .O(\blk000000f4/sig00000359 )
  );
  MUXCY   \blk000000f4/blk0000010e  (
    .CI(\blk000000f4/sig00000359 ),
    .DI(sig00000088),
    .S(\blk000000f4/sig0000034b ),
    .O(\blk000000f4/sig00000358 )
  );
  MUXCY   \blk000000f4/blk0000010d  (
    .CI(\blk000000f4/sig00000358 ),
    .DI(sig00000089),
    .S(\blk000000f4/sig0000034a ),
    .O(\blk000000f4/sig00000357 )
  );
  MUXCY   \blk000000f4/blk0000010c  (
    .CI(\blk000000f4/sig00000357 ),
    .DI(sig0000008a),
    .S(\blk000000f4/sig00000349 ),
    .O(\blk000000f4/sig00000356 )
  );
  MUXCY   \blk000000f4/blk0000010b  (
    .CI(\blk000000f4/sig00000356 ),
    .DI(sig0000008b),
    .S(\blk000000f4/sig00000348 ),
    .O(\blk000000f4/sig00000355 )
  );
  MUXCY   \blk000000f4/blk0000010a  (
    .CI(\blk000000f4/sig00000355 ),
    .DI(sig0000008c),
    .S(\blk000000f4/sig00000347 ),
    .O(\blk000000f4/sig00000354 )
  );
  MUXCY   \blk000000f4/blk00000109  (
    .CI(\blk000000f4/sig00000354 ),
    .DI(sig0000008d),
    .S(\blk000000f4/sig00000346 ),
    .O(\blk000000f4/sig00000353 )
  );
  MUXCY   \blk000000f4/blk00000108  (
    .CI(\blk000000f4/sig00000353 ),
    .DI(sig0000008e),
    .S(\blk000000f4/sig00000345 ),
    .O(\blk000000f4/sig00000352 )
  );
  MUXCY   \blk000000f4/blk00000107  (
    .CI(\blk000000f4/sig00000352 ),
    .DI(sig0000008f),
    .S(\blk000000f4/sig00000344 ),
    .O(\blk000000f4/sig00000351 )
  );
  MUXCY   \blk000000f4/blk00000106  (
    .CI(\blk000000f4/sig00000351 ),
    .DI(sig00000090),
    .S(\blk000000f4/sig00000343 ),
    .O(\blk000000f4/sig00000350 )
  );
  MUXCY   \blk000000f4/blk00000105  (
    .CI(\blk000000f4/sig00000350 ),
    .DI(sig00000091),
    .S(\blk000000f4/sig00000342 ),
    .O(\blk000000f4/sig0000034f )
  );
  MUXCY   \blk000000f4/blk00000104  (
    .CI(\blk000000f4/sig0000034f ),
    .DI(sig00000092),
    .S(\blk000000f4/sig00000341 ),
    .O(\blk000000f4/sig0000034e )
  );
  MUXCY   \blk000000f4/blk00000103  (
    .CI(\blk000000f4/sig0000034e ),
    .DI(sig00000093),
    .S(\blk000000f4/sig0000035b ),
    .O(\blk000000f4/sig0000034d )
  );
  XORCY   \blk000000f4/blk00000102  (
    .CI(\blk000000f4/sig0000035a ),
    .LI(\blk000000f4/sig0000034c ),
    .O(\blk000000f4/sig0000033f )
  );
  XORCY   \blk000000f4/blk00000101  (
    .CI(\blk000000f4/sig00000359 ),
    .LI(\blk000000f4/sig0000034b ),
    .O(\blk000000f4/sig0000033e )
  );
  XORCY   \blk000000f4/blk00000100  (
    .CI(\blk000000f4/sig00000358 ),
    .LI(\blk000000f4/sig0000034a ),
    .O(\blk000000f4/sig0000033d )
  );
  XORCY   \blk000000f4/blk000000ff  (
    .CI(\blk000000f4/sig00000357 ),
    .LI(\blk000000f4/sig00000349 ),
    .O(\blk000000f4/sig0000033c )
  );
  XORCY   \blk000000f4/blk000000fe  (
    .CI(\blk000000f4/sig00000356 ),
    .LI(\blk000000f4/sig00000348 ),
    .O(\blk000000f4/sig0000033b )
  );
  XORCY   \blk000000f4/blk000000fd  (
    .CI(\blk000000f4/sig00000355 ),
    .LI(\blk000000f4/sig00000347 ),
    .O(\blk000000f4/sig0000033a )
  );
  XORCY   \blk000000f4/blk000000fc  (
    .CI(\blk000000f4/sig00000354 ),
    .LI(\blk000000f4/sig00000346 ),
    .O(\blk000000f4/sig00000339 )
  );
  XORCY   \blk000000f4/blk000000fb  (
    .CI(\blk000000f4/sig00000353 ),
    .LI(\blk000000f4/sig00000345 ),
    .O(\blk000000f4/sig00000338 )
  );
  XORCY   \blk000000f4/blk000000fa  (
    .CI(\blk000000f4/sig00000352 ),
    .LI(\blk000000f4/sig00000344 ),
    .O(\blk000000f4/sig00000337 )
  );
  XORCY   \blk000000f4/blk000000f9  (
    .CI(\blk000000f4/sig00000351 ),
    .LI(\blk000000f4/sig00000343 ),
    .O(\blk000000f4/sig00000336 )
  );
  XORCY   \blk000000f4/blk000000f8  (
    .CI(\blk000000f4/sig00000350 ),
    .LI(\blk000000f4/sig00000342 ),
    .O(\blk000000f4/sig00000335 )
  );
  XORCY   \blk000000f4/blk000000f7  (
    .CI(\blk000000f4/sig0000034f ),
    .LI(\blk000000f4/sig00000341 ),
    .O(\blk000000f4/sig00000334 )
  );
  XORCY   \blk000000f4/blk000000f6  (
    .CI(\blk000000f4/sig0000034e ),
    .LI(\blk000000f4/sig0000035b ),
    .O(\blk000000f4/sig00000333 )
  );
  XORCY   \blk000000f4/blk000000f5  (
    .CI(\blk000000f4/sig0000034d ),
    .LI(\blk000000f4/sig00000340 ),
    .O(\NLW_blk000000f4/blk000000f5_O_UNCONNECTED )
  );
  INV   \blk0000012c/blk00000163  (
    .I(sig00000050),
    .O(\blk0000012c/sig000003ac )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk0000012c/blk00000162  (
    .I0(sig00000086),
    .I1(sig00000051),
    .I2(sig00000050),
    .O(\blk0000012c/sig000003ad )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk0000012c/blk00000161  (
    .I0(sig00000083),
    .I1(sig00000050),
    .I2(sig00000061),
    .O(\blk0000012c/sig00000395 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk0000012c/blk00000160  (
    .I0(sig00000082),
    .I1(sig00000050),
    .I2(sig00000060),
    .O(\blk0000012c/sig00000396 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk0000012c/blk0000015f  (
    .I0(sig00000081),
    .I1(sig00000050),
    .I2(sig0000005f),
    .O(\blk0000012c/sig00000397 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk0000012c/blk0000015e  (
    .I0(sig00000080),
    .I1(sig00000050),
    .I2(sig0000005e),
    .O(\blk0000012c/sig00000398 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk0000012c/blk0000015d  (
    .I0(sig0000007f),
    .I1(sig00000050),
    .I2(sig0000005d),
    .O(\blk0000012c/sig00000399 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk0000012c/blk0000015c  (
    .I0(sig0000007e),
    .I1(sig00000050),
    .I2(sig0000005c),
    .O(\blk0000012c/sig0000039a )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk0000012c/blk0000015b  (
    .I0(sig0000007d),
    .I1(sig00000050),
    .I2(sig0000005b),
    .O(\blk0000012c/sig0000039b )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk0000012c/blk0000015a  (
    .I0(sig0000007c),
    .I1(sig00000050),
    .I2(sig0000005a),
    .O(\blk0000012c/sig0000039c )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk0000012c/blk00000159  (
    .I0(sig0000007b),
    .I1(sig00000050),
    .I2(sig00000059),
    .O(\blk0000012c/sig0000039d )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk0000012c/blk00000158  (
    .I0(sig00000086),
    .I1(sig00000051),
    .I2(sig00000050),
    .O(\blk0000012c/sig00000392 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk0000012c/blk00000157  (
    .I0(sig00000085),
    .I1(sig00000051),
    .I2(sig00000050),
    .O(\blk0000012c/sig00000393 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk0000012c/blk00000156  (
    .I0(sig00000084),
    .I1(sig00000050),
    .I2(sig00000062),
    .O(\blk0000012c/sig00000394 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk0000012c/blk00000155  (
    .I0(sig0000007a),
    .I1(sig00000050),
    .I2(sig00000058),
    .O(\blk0000012c/sig0000039e )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000012c/blk00000154  (
    .C(clk),
    .D(\blk0000012c/sig00000391 ),
    .Q(sig0000001f)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000012c/blk00000153  (
    .C(clk),
    .D(\blk0000012c/sig00000390 ),
    .Q(sig00000020)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000012c/blk00000152  (
    .C(clk),
    .D(\blk0000012c/sig0000038f ),
    .Q(sig00000021)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000012c/blk00000151  (
    .C(clk),
    .D(\blk0000012c/sig0000038e ),
    .Q(sig00000022)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000012c/blk00000150  (
    .C(clk),
    .D(\blk0000012c/sig0000038d ),
    .Q(sig00000023)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000012c/blk0000014f  (
    .C(clk),
    .D(\blk0000012c/sig0000038c ),
    .Q(sig00000024)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000012c/blk0000014e  (
    .C(clk),
    .D(\blk0000012c/sig0000038b ),
    .Q(sig00000025)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000012c/blk0000014d  (
    .C(clk),
    .D(\blk0000012c/sig0000038a ),
    .Q(sig00000026)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000012c/blk0000014c  (
    .C(clk),
    .D(\blk0000012c/sig00000389 ),
    .Q(sig00000027)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000012c/blk0000014b  (
    .C(clk),
    .D(\blk0000012c/sig00000388 ),
    .Q(sig00000028)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000012c/blk0000014a  (
    .C(clk),
    .D(\blk0000012c/sig00000387 ),
    .Q(sig00000029)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000012c/blk00000149  (
    .C(clk),
    .D(\blk0000012c/sig00000386 ),
    .Q(sig0000002a)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000012c/blk00000148  (
    .C(clk),
    .D(\blk0000012c/sig00000385 ),
    .Q(sig0000002b)
  );
  MUXCY   \blk0000012c/blk00000147  (
    .CI(\blk0000012c/sig000003ac ),
    .DI(sig0000007a),
    .S(\blk0000012c/sig0000039e ),
    .O(\blk0000012c/sig000003ab )
  );
  MUXCY   \blk0000012c/blk00000146  (
    .CI(\blk0000012c/sig000003ab ),
    .DI(sig0000007b),
    .S(\blk0000012c/sig0000039d ),
    .O(\blk0000012c/sig000003aa )
  );
  MUXCY   \blk0000012c/blk00000145  (
    .CI(\blk0000012c/sig000003aa ),
    .DI(sig0000007c),
    .S(\blk0000012c/sig0000039c ),
    .O(\blk0000012c/sig000003a9 )
  );
  MUXCY   \blk0000012c/blk00000144  (
    .CI(\blk0000012c/sig000003a9 ),
    .DI(sig0000007d),
    .S(\blk0000012c/sig0000039b ),
    .O(\blk0000012c/sig000003a8 )
  );
  MUXCY   \blk0000012c/blk00000143  (
    .CI(\blk0000012c/sig000003a8 ),
    .DI(sig0000007e),
    .S(\blk0000012c/sig0000039a ),
    .O(\blk0000012c/sig000003a7 )
  );
  MUXCY   \blk0000012c/blk00000142  (
    .CI(\blk0000012c/sig000003a7 ),
    .DI(sig0000007f),
    .S(\blk0000012c/sig00000399 ),
    .O(\blk0000012c/sig000003a6 )
  );
  MUXCY   \blk0000012c/blk00000141  (
    .CI(\blk0000012c/sig000003a6 ),
    .DI(sig00000080),
    .S(\blk0000012c/sig00000398 ),
    .O(\blk0000012c/sig000003a5 )
  );
  MUXCY   \blk0000012c/blk00000140  (
    .CI(\blk0000012c/sig000003a5 ),
    .DI(sig00000081),
    .S(\blk0000012c/sig00000397 ),
    .O(\blk0000012c/sig000003a4 )
  );
  MUXCY   \blk0000012c/blk0000013f  (
    .CI(\blk0000012c/sig000003a4 ),
    .DI(sig00000082),
    .S(\blk0000012c/sig00000396 ),
    .O(\blk0000012c/sig000003a3 )
  );
  MUXCY   \blk0000012c/blk0000013e  (
    .CI(\blk0000012c/sig000003a3 ),
    .DI(sig00000083),
    .S(\blk0000012c/sig00000395 ),
    .O(\blk0000012c/sig000003a2 )
  );
  MUXCY   \blk0000012c/blk0000013d  (
    .CI(\blk0000012c/sig000003a2 ),
    .DI(sig00000084),
    .S(\blk0000012c/sig00000394 ),
    .O(\blk0000012c/sig000003a1 )
  );
  MUXCY   \blk0000012c/blk0000013c  (
    .CI(\blk0000012c/sig000003a1 ),
    .DI(sig00000085),
    .S(\blk0000012c/sig00000393 ),
    .O(\blk0000012c/sig000003a0 )
  );
  MUXCY   \blk0000012c/blk0000013b  (
    .CI(\blk0000012c/sig000003a0 ),
    .DI(sig00000086),
    .S(\blk0000012c/sig000003ad ),
    .O(\blk0000012c/sig0000039f )
  );
  XORCY   \blk0000012c/blk0000013a  (
    .CI(\blk0000012c/sig000003ac ),
    .LI(\blk0000012c/sig0000039e ),
    .O(\blk0000012c/sig00000391 )
  );
  XORCY   \blk0000012c/blk00000139  (
    .CI(\blk0000012c/sig000003ab ),
    .LI(\blk0000012c/sig0000039d ),
    .O(\blk0000012c/sig00000390 )
  );
  XORCY   \blk0000012c/blk00000138  (
    .CI(\blk0000012c/sig000003aa ),
    .LI(\blk0000012c/sig0000039c ),
    .O(\blk0000012c/sig0000038f )
  );
  XORCY   \blk0000012c/blk00000137  (
    .CI(\blk0000012c/sig000003a9 ),
    .LI(\blk0000012c/sig0000039b ),
    .O(\blk0000012c/sig0000038e )
  );
  XORCY   \blk0000012c/blk00000136  (
    .CI(\blk0000012c/sig000003a8 ),
    .LI(\blk0000012c/sig0000039a ),
    .O(\blk0000012c/sig0000038d )
  );
  XORCY   \blk0000012c/blk00000135  (
    .CI(\blk0000012c/sig000003a7 ),
    .LI(\blk0000012c/sig00000399 ),
    .O(\blk0000012c/sig0000038c )
  );
  XORCY   \blk0000012c/blk00000134  (
    .CI(\blk0000012c/sig000003a6 ),
    .LI(\blk0000012c/sig00000398 ),
    .O(\blk0000012c/sig0000038b )
  );
  XORCY   \blk0000012c/blk00000133  (
    .CI(\blk0000012c/sig000003a5 ),
    .LI(\blk0000012c/sig00000397 ),
    .O(\blk0000012c/sig0000038a )
  );
  XORCY   \blk0000012c/blk00000132  (
    .CI(\blk0000012c/sig000003a4 ),
    .LI(\blk0000012c/sig00000396 ),
    .O(\blk0000012c/sig00000389 )
  );
  XORCY   \blk0000012c/blk00000131  (
    .CI(\blk0000012c/sig000003a3 ),
    .LI(\blk0000012c/sig00000395 ),
    .O(\blk0000012c/sig00000388 )
  );
  XORCY   \blk0000012c/blk00000130  (
    .CI(\blk0000012c/sig000003a2 ),
    .LI(\blk0000012c/sig00000394 ),
    .O(\blk0000012c/sig00000387 )
  );
  XORCY   \blk0000012c/blk0000012f  (
    .CI(\blk0000012c/sig000003a1 ),
    .LI(\blk0000012c/sig00000393 ),
    .O(\blk0000012c/sig00000386 )
  );
  XORCY   \blk0000012c/blk0000012e  (
    .CI(\blk0000012c/sig000003a0 ),
    .LI(\blk0000012c/sig000003ad ),
    .O(\blk0000012c/sig00000385 )
  );
  XORCY   \blk0000012c/blk0000012d  (
    .CI(\blk0000012c/sig0000039f ),
    .LI(\blk0000012c/sig00000392 ),
    .O(\NLW_blk0000012c/blk0000012d_O_UNCONNECTED )
  );
  INV   \blk00000164/blk0000019b  (
    .I(sig00000051),
    .O(\blk00000164/sig000003fe )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk00000164/blk0000019a  (
    .I0(sig00000051),
    .I1(sig00000086),
    .I2(sig00000051),
    .O(\blk00000164/sig000003ff )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk00000164/blk00000199  (
    .I0(sig00000077),
    .I1(sig00000051),
    .I2(sig0000006c),
    .O(\blk00000164/sig000003e7 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk00000164/blk00000198  (
    .I0(sig00000076),
    .I1(sig00000051),
    .I2(sig0000006b),
    .O(\blk00000164/sig000003e8 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk00000164/blk00000197  (
    .I0(sig00000075),
    .I1(sig00000051),
    .I2(sig0000006a),
    .O(\blk00000164/sig000003e9 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk00000164/blk00000196  (
    .I0(sig00000074),
    .I1(sig00000051),
    .I2(sig00000069),
    .O(\blk00000164/sig000003ea )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk00000164/blk00000195  (
    .I0(sig00000073),
    .I1(sig00000051),
    .I2(sig00000068),
    .O(\blk00000164/sig000003eb )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk00000164/blk00000194  (
    .I0(sig00000072),
    .I1(sig00000051),
    .I2(sig00000067),
    .O(\blk00000164/sig000003ec )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk00000164/blk00000193  (
    .I0(sig00000071),
    .I1(sig00000051),
    .I2(sig00000066),
    .O(\blk00000164/sig000003ed )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk00000164/blk00000192  (
    .I0(sig00000070),
    .I1(sig00000051),
    .I2(sig00000065),
    .O(\blk00000164/sig000003ee )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk00000164/blk00000191  (
    .I0(sig0000006f),
    .I1(sig00000051),
    .I2(sig00000064),
    .O(\blk00000164/sig000003ef )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk00000164/blk00000190  (
    .I0(sig00000051),
    .I1(sig00000086),
    .I2(sig00000051),
    .O(\blk00000164/sig000003e4 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk00000164/blk0000018f  (
    .I0(sig00000079),
    .I1(sig00000086),
    .I2(sig00000051),
    .O(\blk00000164/sig000003e5 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk00000164/blk0000018e  (
    .I0(sig00000078),
    .I1(sig00000051),
    .I2(sig0000006d),
    .O(\blk00000164/sig000003e6 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk00000164/blk0000018d  (
    .I0(sig0000006e),
    .I1(sig00000051),
    .I2(sig00000063),
    .O(\blk00000164/sig000003f0 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000164/blk0000018c  (
    .C(clk),
    .D(\blk00000164/sig000003e3 ),
    .Q(sig00000012)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000164/blk0000018b  (
    .C(clk),
    .D(\blk00000164/sig000003e2 ),
    .Q(sig00000013)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000164/blk0000018a  (
    .C(clk),
    .D(\blk00000164/sig000003e1 ),
    .Q(sig00000014)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000164/blk00000189  (
    .C(clk),
    .D(\blk00000164/sig000003e0 ),
    .Q(sig00000015)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000164/blk00000188  (
    .C(clk),
    .D(\blk00000164/sig000003df ),
    .Q(sig00000016)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000164/blk00000187  (
    .C(clk),
    .D(\blk00000164/sig000003de ),
    .Q(sig00000017)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000164/blk00000186  (
    .C(clk),
    .D(\blk00000164/sig000003dd ),
    .Q(sig00000018)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000164/blk00000185  (
    .C(clk),
    .D(\blk00000164/sig000003dc ),
    .Q(sig00000019)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000164/blk00000184  (
    .C(clk),
    .D(\blk00000164/sig000003db ),
    .Q(sig0000001a)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000164/blk00000183  (
    .C(clk),
    .D(\blk00000164/sig000003da ),
    .Q(sig0000001b)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000164/blk00000182  (
    .C(clk),
    .D(\blk00000164/sig000003d9 ),
    .Q(sig0000001c)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000164/blk00000181  (
    .C(clk),
    .D(\blk00000164/sig000003d8 ),
    .Q(sig0000001d)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000164/blk00000180  (
    .C(clk),
    .D(\blk00000164/sig000003d7 ),
    .Q(sig0000001e)
  );
  MUXCY   \blk00000164/blk0000017f  (
    .CI(\blk00000164/sig000003fe ),
    .DI(sig0000006e),
    .S(\blk00000164/sig000003f0 ),
    .O(\blk00000164/sig000003fd )
  );
  MUXCY   \blk00000164/blk0000017e  (
    .CI(\blk00000164/sig000003fd ),
    .DI(sig0000006f),
    .S(\blk00000164/sig000003ef ),
    .O(\blk00000164/sig000003fc )
  );
  MUXCY   \blk00000164/blk0000017d  (
    .CI(\blk00000164/sig000003fc ),
    .DI(sig00000070),
    .S(\blk00000164/sig000003ee ),
    .O(\blk00000164/sig000003fb )
  );
  MUXCY   \blk00000164/blk0000017c  (
    .CI(\blk00000164/sig000003fb ),
    .DI(sig00000071),
    .S(\blk00000164/sig000003ed ),
    .O(\blk00000164/sig000003fa )
  );
  MUXCY   \blk00000164/blk0000017b  (
    .CI(\blk00000164/sig000003fa ),
    .DI(sig00000072),
    .S(\blk00000164/sig000003ec ),
    .O(\blk00000164/sig000003f9 )
  );
  MUXCY   \blk00000164/blk0000017a  (
    .CI(\blk00000164/sig000003f9 ),
    .DI(sig00000073),
    .S(\blk00000164/sig000003eb ),
    .O(\blk00000164/sig000003f8 )
  );
  MUXCY   \blk00000164/blk00000179  (
    .CI(\blk00000164/sig000003f8 ),
    .DI(sig00000074),
    .S(\blk00000164/sig000003ea ),
    .O(\blk00000164/sig000003f7 )
  );
  MUXCY   \blk00000164/blk00000178  (
    .CI(\blk00000164/sig000003f7 ),
    .DI(sig00000075),
    .S(\blk00000164/sig000003e9 ),
    .O(\blk00000164/sig000003f6 )
  );
  MUXCY   \blk00000164/blk00000177  (
    .CI(\blk00000164/sig000003f6 ),
    .DI(sig00000076),
    .S(\blk00000164/sig000003e8 ),
    .O(\blk00000164/sig000003f5 )
  );
  MUXCY   \blk00000164/blk00000176  (
    .CI(\blk00000164/sig000003f5 ),
    .DI(sig00000077),
    .S(\blk00000164/sig000003e7 ),
    .O(\blk00000164/sig000003f4 )
  );
  MUXCY   \blk00000164/blk00000175  (
    .CI(\blk00000164/sig000003f4 ),
    .DI(sig00000078),
    .S(\blk00000164/sig000003e6 ),
    .O(\blk00000164/sig000003f3 )
  );
  MUXCY   \blk00000164/blk00000174  (
    .CI(\blk00000164/sig000003f3 ),
    .DI(sig00000079),
    .S(\blk00000164/sig000003e5 ),
    .O(\blk00000164/sig000003f2 )
  );
  MUXCY   \blk00000164/blk00000173  (
    .CI(\blk00000164/sig000003f2 ),
    .DI(sig00000051),
    .S(\blk00000164/sig000003ff ),
    .O(\blk00000164/sig000003f1 )
  );
  XORCY   \blk00000164/blk00000172  (
    .CI(\blk00000164/sig000003fe ),
    .LI(\blk00000164/sig000003f0 ),
    .O(\blk00000164/sig000003e3 )
  );
  XORCY   \blk00000164/blk00000171  (
    .CI(\blk00000164/sig000003fd ),
    .LI(\blk00000164/sig000003ef ),
    .O(\blk00000164/sig000003e2 )
  );
  XORCY   \blk00000164/blk00000170  (
    .CI(\blk00000164/sig000003fc ),
    .LI(\blk00000164/sig000003ee ),
    .O(\blk00000164/sig000003e1 )
  );
  XORCY   \blk00000164/blk0000016f  (
    .CI(\blk00000164/sig000003fb ),
    .LI(\blk00000164/sig000003ed ),
    .O(\blk00000164/sig000003e0 )
  );
  XORCY   \blk00000164/blk0000016e  (
    .CI(\blk00000164/sig000003fa ),
    .LI(\blk00000164/sig000003ec ),
    .O(\blk00000164/sig000003df )
  );
  XORCY   \blk00000164/blk0000016d  (
    .CI(\blk00000164/sig000003f9 ),
    .LI(\blk00000164/sig000003eb ),
    .O(\blk00000164/sig000003de )
  );
  XORCY   \blk00000164/blk0000016c  (
    .CI(\blk00000164/sig000003f8 ),
    .LI(\blk00000164/sig000003ea ),
    .O(\blk00000164/sig000003dd )
  );
  XORCY   \blk00000164/blk0000016b  (
    .CI(\blk00000164/sig000003f7 ),
    .LI(\blk00000164/sig000003e9 ),
    .O(\blk00000164/sig000003dc )
  );
  XORCY   \blk00000164/blk0000016a  (
    .CI(\blk00000164/sig000003f6 ),
    .LI(\blk00000164/sig000003e8 ),
    .O(\blk00000164/sig000003db )
  );
  XORCY   \blk00000164/blk00000169  (
    .CI(\blk00000164/sig000003f5 ),
    .LI(\blk00000164/sig000003e7 ),
    .O(\blk00000164/sig000003da )
  );
  XORCY   \blk00000164/blk00000168  (
    .CI(\blk00000164/sig000003f4 ),
    .LI(\blk00000164/sig000003e6 ),
    .O(\blk00000164/sig000003d9 )
  );
  XORCY   \blk00000164/blk00000167  (
    .CI(\blk00000164/sig000003f3 ),
    .LI(\blk00000164/sig000003e5 ),
    .O(\blk00000164/sig000003d8 )
  );
  XORCY   \blk00000164/blk00000166  (
    .CI(\blk00000164/sig000003f2 ),
    .LI(\blk00000164/sig000003ff ),
    .O(\blk00000164/sig000003d7 )
  );
  XORCY   \blk00000164/blk00000165  (
    .CI(\blk00000164/sig000003f1 ),
    .LI(\blk00000164/sig000003e4 ),
    .O(\NLW_blk00000164/blk00000165_O_UNCONNECTED )
  );
  INV   \blk000001b7/blk000001c9  (
    .I(sig000000e4),
    .O(\blk000001b7/sig00000410 )
  );
  LUT1 #(
    .INIT ( 2'h2 ))
  \blk000001b7/blk000001c8  (
    .I0(sig000000e3),
    .O(\blk000001b7/sig00000417 )
  );
  LUT1 #(
    .INIT ( 2'h2 ))
  \blk000001b7/blk000001c7  (
    .I0(sig000000e2),
    .O(\blk000001b7/sig00000416 )
  );
  LUT1 #(
    .INIT ( 2'h2 ))
  \blk000001b7/blk000001c6  (
    .I0(sig000000e1),
    .O(\blk000001b7/sig00000415 )
  );
  FDRE #(
    .INIT ( 1'b0 ))
  \blk000001b7/blk000001c5  (
    .C(clk),
    .CE(sig000000e7),
    .D(\blk000001b7/sig0000040c ),
    .R(sig000000e9),
    .Q(sig000000e4)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  \blk000001b7/blk000001c4  (
    .C(clk),
    .CE(sig000000e7),
    .D(\blk000001b7/sig0000040f ),
    .R(sig000000e9),
    .Q(sig000000e3)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  \blk000001b7/blk000001c3  (
    .C(clk),
    .CE(sig000000e7),
    .D(\blk000001b7/sig0000040e ),
    .R(sig000000e9),
    .Q(sig000000e2)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  \blk000001b7/blk000001c2  (
    .C(clk),
    .CE(sig000000e7),
    .D(\blk000001b7/sig0000040d ),
    .R(sig000000e9),
    .Q(sig000000e1)
  );
  MUXCY   \blk000001b7/blk000001c1  (
    .CI(\blk000001b7/sig0000040b ),
    .DI(sig000000e4),
    .S(\blk000001b7/sig00000410 ),
    .O(\blk000001b7/sig00000414 )
  );
  MUXCY   \blk000001b7/blk000001c0  (
    .CI(\blk000001b7/sig00000414 ),
    .DI(sig000000e3),
    .S(\blk000001b7/sig00000417 ),
    .O(\blk000001b7/sig00000413 )
  );
  MUXCY   \blk000001b7/blk000001bf  (
    .CI(\blk000001b7/sig00000413 ),
    .DI(sig000000e2),
    .S(\blk000001b7/sig00000416 ),
    .O(\blk000001b7/sig00000412 )
  );
  MUXCY   \blk000001b7/blk000001be  (
    .CI(\blk000001b7/sig00000412 ),
    .DI(sig000000e1),
    .S(\blk000001b7/sig00000415 ),
    .O(\blk000001b7/sig00000411 )
  );
  XORCY   \blk000001b7/blk000001bd  (
    .CI(\blk000001b7/sig00000414 ),
    .LI(\blk000001b7/sig00000417 ),
    .O(\blk000001b7/sig0000040f )
  );
  XORCY   \blk000001b7/blk000001bc  (
    .CI(\blk000001b7/sig00000413 ),
    .LI(\blk000001b7/sig00000416 ),
    .O(\blk000001b7/sig0000040e )
  );
  XORCY   \blk000001b7/blk000001bb  (
    .CI(\blk000001b7/sig00000412 ),
    .LI(\blk000001b7/sig00000415 ),
    .O(\blk000001b7/sig0000040d )
  );
  XORCY   \blk000001b7/blk000001ba  (
    .CI(\blk000001b7/sig00000411 ),
    .LI(\blk000001b7/sig0000040b ),
    .O(\NLW_blk000001b7/blk000001ba_O_UNCONNECTED )
  );
  XORCY   \blk000001b7/blk000001b9  (
    .CI(\blk000001b7/sig0000040b ),
    .LI(\blk000001b7/sig00000410 ),
    .O(\blk000001b7/sig0000040c )
  );
  GND   \blk000001b7/blk000001b8  (
    .G(\blk000001b7/sig0000040b )
  );
  INV   \blk000001ca/blk000001dc  (
    .I(sig00000055),
    .O(\blk000001ca/sig00000428 )
  );
  LUT1 #(
    .INIT ( 2'h2 ))
  \blk000001ca/blk000001db  (
    .I0(sig00000056),
    .O(\blk000001ca/sig0000042f )
  );
  LUT1 #(
    .INIT ( 2'h2 ))
  \blk000001ca/blk000001da  (
    .I0(sig00000057),
    .O(\blk000001ca/sig0000042e )
  );
  LUT1 #(
    .INIT ( 2'h2 ))
  \blk000001ca/blk000001d9  (
    .I0(sig000000e5),
    .O(\blk000001ca/sig0000042d )
  );
  FDRE #(
    .INIT ( 1'b0 ))
  \blk000001ca/blk000001d8  (
    .C(clk),
    .CE(sig000000e7),
    .D(\blk000001ca/sig00000424 ),
    .R(sig000000e9),
    .Q(sig00000055)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  \blk000001ca/blk000001d7  (
    .C(clk),
    .CE(sig000000e7),
    .D(\blk000001ca/sig00000427 ),
    .R(sig000000e9),
    .Q(sig00000056)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  \blk000001ca/blk000001d6  (
    .C(clk),
    .CE(sig000000e7),
    .D(\blk000001ca/sig00000426 ),
    .R(sig000000e9),
    .Q(sig00000057)
  );
  FDRE #(
    .INIT ( 1'b0 ))
  \blk000001ca/blk000001d5  (
    .C(clk),
    .CE(sig000000e7),
    .D(\blk000001ca/sig00000425 ),
    .R(sig000000e9),
    .Q(sig000000e5)
  );
  MUXCY   \blk000001ca/blk000001d4  (
    .CI(\blk000001ca/sig00000423 ),
    .DI(sig00000055),
    .S(\blk000001ca/sig00000428 ),
    .O(\blk000001ca/sig0000042c )
  );
  MUXCY   \blk000001ca/blk000001d3  (
    .CI(\blk000001ca/sig0000042c ),
    .DI(sig00000056),
    .S(\blk000001ca/sig0000042f ),
    .O(\blk000001ca/sig0000042b )
  );
  MUXCY   \blk000001ca/blk000001d2  (
    .CI(\blk000001ca/sig0000042b ),
    .DI(sig00000057),
    .S(\blk000001ca/sig0000042e ),
    .O(\blk000001ca/sig0000042a )
  );
  MUXCY   \blk000001ca/blk000001d1  (
    .CI(\blk000001ca/sig0000042a ),
    .DI(sig000000e5),
    .S(\blk000001ca/sig0000042d ),
    .O(\blk000001ca/sig00000429 )
  );
  XORCY   \blk000001ca/blk000001d0  (
    .CI(\blk000001ca/sig0000042c ),
    .LI(\blk000001ca/sig0000042f ),
    .O(\blk000001ca/sig00000427 )
  );
  XORCY   \blk000001ca/blk000001cf  (
    .CI(\blk000001ca/sig0000042b ),
    .LI(\blk000001ca/sig0000042e ),
    .O(\blk000001ca/sig00000426 )
  );
  XORCY   \blk000001ca/blk000001ce  (
    .CI(\blk000001ca/sig0000042a ),
    .LI(\blk000001ca/sig0000042d ),
    .O(\blk000001ca/sig00000425 )
  );
  XORCY   \blk000001ca/blk000001cd  (
    .CI(\blk000001ca/sig00000429 ),
    .LI(\blk000001ca/sig00000423 ),
    .O(\NLW_blk000001ca/blk000001cd_O_UNCONNECTED )
  );
  XORCY   \blk000001ca/blk000001cc  (
    .CI(\blk000001ca/sig00000423 ),
    .LI(\blk000001ca/sig00000428 ),
    .O(\blk000001ca/sig00000424 )
  );
  GND   \blk000001ca/blk000001cb  (
    .G(\blk000001ca/sig00000423 )
  );
  INV   \blk000001e5/blk00000219  (
    .I(sig0000014d),
    .O(\blk000001e5/sig00000471 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk000001e5/blk00000218  (
    .I0(sig00000166),
    .I1(sig00000159),
    .I2(sig0000014d),
    .O(\blk000001e5/sig00000472 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk000001e5/blk00000217  (
    .I0(sig00000163),
    .I1(sig00000158),
    .I2(sig0000014d),
    .O(\blk000001e5/sig0000045a )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000001e5/blk00000216  (
    .I0(sig00000162),
    .I1(sig0000014d),
    .O(\blk000001e5/sig0000045b )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000001e5/blk00000215  (
    .I0(sig00000161),
    .I1(sig0000014d),
    .O(\blk000001e5/sig0000045c )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000001e5/blk00000214  (
    .I0(sig00000160),
    .I1(sig0000014d),
    .O(\blk000001e5/sig0000045d )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000001e5/blk00000213  (
    .I0(sig0000015f),
    .I1(sig0000014d),
    .O(\blk000001e5/sig0000045e )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000001e5/blk00000212  (
    .I0(sig0000015e),
    .I1(sig0000014d),
    .O(\blk000001e5/sig0000045f )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000001e5/blk00000211  (
    .I0(sig0000015d),
    .I1(sig0000014d),
    .O(\blk000001e5/sig00000460 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000001e5/blk00000210  (
    .I0(sig0000015c),
    .I1(sig0000014d),
    .O(\blk000001e5/sig00000461 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000001e5/blk0000020f  (
    .I0(sig0000015b),
    .I1(sig0000014d),
    .O(\blk000001e5/sig00000462 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk000001e5/blk0000020e  (
    .I0(sig00000166),
    .I1(sig00000159),
    .I2(sig0000014d),
    .O(\blk000001e5/sig00000457 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk000001e5/blk0000020d  (
    .I0(sig00000165),
    .I1(sig00000159),
    .I2(sig0000014d),
    .O(\blk000001e5/sig00000458 )
  );
  LUT3 #(
    .INIT ( 8'h69 ))
  \blk000001e5/blk0000020c  (
    .I0(sig00000164),
    .I1(sig00000159),
    .I2(sig0000014d),
    .O(\blk000001e5/sig00000459 )
  );
  LUT2 #(
    .INIT ( 4'h9 ))
  \blk000001e5/blk0000020b  (
    .I0(sig0000015a),
    .I1(sig0000014d),
    .O(\blk000001e5/sig00000463 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000001e5/blk0000020a  (
    .C(clk),
    .D(\blk000001e5/sig00000456 ),
    .Q(sig0000014e)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000001e5/blk00000209  (
    .C(clk),
    .D(\blk000001e5/sig00000455 ),
    .Q(sig0000014f)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000001e5/blk00000208  (
    .C(clk),
    .D(\blk000001e5/sig00000454 ),
    .Q(sig00000150)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000001e5/blk00000207  (
    .C(clk),
    .D(\blk000001e5/sig00000453 ),
    .Q(sig00000151)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000001e5/blk00000206  (
    .C(clk),
    .D(\blk000001e5/sig00000452 ),
    .Q(sig00000152)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000001e5/blk00000205  (
    .C(clk),
    .D(\blk000001e5/sig00000451 ),
    .Q(sig00000153)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000001e5/blk00000204  (
    .C(clk),
    .D(\blk000001e5/sig00000450 ),
    .Q(sig00000154)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000001e5/blk00000203  (
    .C(clk),
    .D(\blk000001e5/sig0000044f ),
    .Q(sig00000155)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000001e5/blk00000202  (
    .C(clk),
    .D(\blk000001e5/sig0000044e ),
    .Q(sig00000156)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk000001e5/blk00000201  (
    .C(clk),
    .D(\blk000001e5/sig0000044d ),
    .Q(sig00000157)
  );
  MUXCY   \blk000001e5/blk00000200  (
    .CI(\blk000001e5/sig00000471 ),
    .DI(sig0000015a),
    .S(\blk000001e5/sig00000463 ),
    .O(\blk000001e5/sig00000470 )
  );
  MUXCY   \blk000001e5/blk000001ff  (
    .CI(\blk000001e5/sig00000470 ),
    .DI(sig0000015b),
    .S(\blk000001e5/sig00000462 ),
    .O(\blk000001e5/sig0000046f )
  );
  MUXCY   \blk000001e5/blk000001fe  (
    .CI(\blk000001e5/sig0000046f ),
    .DI(sig0000015c),
    .S(\blk000001e5/sig00000461 ),
    .O(\blk000001e5/sig0000046e )
  );
  MUXCY   \blk000001e5/blk000001fd  (
    .CI(\blk000001e5/sig0000046e ),
    .DI(sig0000015d),
    .S(\blk000001e5/sig00000460 ),
    .O(\blk000001e5/sig0000046d )
  );
  MUXCY   \blk000001e5/blk000001fc  (
    .CI(\blk000001e5/sig0000046d ),
    .DI(sig0000015e),
    .S(\blk000001e5/sig0000045f ),
    .O(\blk000001e5/sig0000046c )
  );
  MUXCY   \blk000001e5/blk000001fb  (
    .CI(\blk000001e5/sig0000046c ),
    .DI(sig0000015f),
    .S(\blk000001e5/sig0000045e ),
    .O(\blk000001e5/sig0000046b )
  );
  MUXCY   \blk000001e5/blk000001fa  (
    .CI(\blk000001e5/sig0000046b ),
    .DI(sig00000160),
    .S(\blk000001e5/sig0000045d ),
    .O(\blk000001e5/sig0000046a )
  );
  MUXCY   \blk000001e5/blk000001f9  (
    .CI(\blk000001e5/sig0000046a ),
    .DI(sig00000161),
    .S(\blk000001e5/sig0000045c ),
    .O(\blk000001e5/sig00000469 )
  );
  MUXCY   \blk000001e5/blk000001f8  (
    .CI(\blk000001e5/sig00000469 ),
    .DI(sig00000162),
    .S(\blk000001e5/sig0000045b ),
    .O(\blk000001e5/sig00000468 )
  );
  MUXCY   \blk000001e5/blk000001f7  (
    .CI(\blk000001e5/sig00000468 ),
    .DI(sig00000163),
    .S(\blk000001e5/sig0000045a ),
    .O(\blk000001e5/sig00000467 )
  );
  MUXCY   \blk000001e5/blk000001f6  (
    .CI(\blk000001e5/sig00000467 ),
    .DI(sig00000164),
    .S(\blk000001e5/sig00000459 ),
    .O(\blk000001e5/sig00000466 )
  );
  MUXCY   \blk000001e5/blk000001f5  (
    .CI(\blk000001e5/sig00000466 ),
    .DI(sig00000165),
    .S(\blk000001e5/sig00000458 ),
    .O(\blk000001e5/sig00000465 )
  );
  MUXCY   \blk000001e5/blk000001f4  (
    .CI(\blk000001e5/sig00000465 ),
    .DI(sig00000166),
    .S(\blk000001e5/sig00000472 ),
    .O(\blk000001e5/sig00000464 )
  );
  XORCY   \blk000001e5/blk000001f3  (
    .CI(\blk000001e5/sig00000471 ),
    .LI(\blk000001e5/sig00000463 ),
    .O(\NLW_blk000001e5/blk000001f3_O_UNCONNECTED )
  );
  XORCY   \blk000001e5/blk000001f2  (
    .CI(\blk000001e5/sig00000470 ),
    .LI(\blk000001e5/sig00000462 ),
    .O(\NLW_blk000001e5/blk000001f2_O_UNCONNECTED )
  );
  XORCY   \blk000001e5/blk000001f1  (
    .CI(\blk000001e5/sig0000046f ),
    .LI(\blk000001e5/sig00000461 ),
    .O(\NLW_blk000001e5/blk000001f1_O_UNCONNECTED )
  );
  XORCY   \blk000001e5/blk000001f0  (
    .CI(\blk000001e5/sig0000046e ),
    .LI(\blk000001e5/sig00000460 ),
    .O(\blk000001e5/sig00000456 )
  );
  XORCY   \blk000001e5/blk000001ef  (
    .CI(\blk000001e5/sig0000046d ),
    .LI(\blk000001e5/sig0000045f ),
    .O(\blk000001e5/sig00000455 )
  );
  XORCY   \blk000001e5/blk000001ee  (
    .CI(\blk000001e5/sig0000046c ),
    .LI(\blk000001e5/sig0000045e ),
    .O(\blk000001e5/sig00000454 )
  );
  XORCY   \blk000001e5/blk000001ed  (
    .CI(\blk000001e5/sig0000046b ),
    .LI(\blk000001e5/sig0000045d ),
    .O(\blk000001e5/sig00000453 )
  );
  XORCY   \blk000001e5/blk000001ec  (
    .CI(\blk000001e5/sig0000046a ),
    .LI(\blk000001e5/sig0000045c ),
    .O(\blk000001e5/sig00000452 )
  );
  XORCY   \blk000001e5/blk000001eb  (
    .CI(\blk000001e5/sig00000469 ),
    .LI(\blk000001e5/sig0000045b ),
    .O(\blk000001e5/sig00000451 )
  );
  XORCY   \blk000001e5/blk000001ea  (
    .CI(\blk000001e5/sig00000468 ),
    .LI(\blk000001e5/sig0000045a ),
    .O(\blk000001e5/sig00000450 )
  );
  XORCY   \blk000001e5/blk000001e9  (
    .CI(\blk000001e5/sig00000467 ),
    .LI(\blk000001e5/sig00000459 ),
    .O(\blk000001e5/sig0000044f )
  );
  XORCY   \blk000001e5/blk000001e8  (
    .CI(\blk000001e5/sig00000466 ),
    .LI(\blk000001e5/sig00000458 ),
    .O(\blk000001e5/sig0000044e )
  );
  XORCY   \blk000001e5/blk000001e7  (
    .CI(\blk000001e5/sig00000465 ),
    .LI(\blk000001e5/sig00000472 ),
    .O(\blk000001e5/sig0000044d )
  );
  XORCY   \blk000001e5/blk000001e6  (
    .CI(\blk000001e5/sig00000464 ),
    .LI(\blk000001e5/sig00000457 ),
    .O(\NLW_blk000001e5/blk000001e6_O_UNCONNECTED )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000029a/blk000002a6  (
    .C(clk),
    .D(sig0000011d),
    .Q(sig0000011e)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000029a/blk000002a5  (
    .C(clk),
    .D(sig0000011c),
    .Q(sig0000011f)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000029a/blk000002a4  (
    .C(clk),
    .D(sig0000011c),
    .Q(sig00000120)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000029a/blk000002a3  (
    .C(clk),
    .D(sig0000011d),
    .Q(sig00000121)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000029a/blk000002a2  (
    .C(clk),
    .D(sig0000011c),
    .Q(sig00000122)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000029a/blk000002a1  (
    .C(clk),
    .D(sig0000011c),
    .Q(sig00000123)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000029a/blk000002a0  (
    .C(clk),
    .D(sig0000011d),
    .Q(sig00000124)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000029a/blk0000029f  (
    .C(clk),
    .D(sig0000011c),
    .Q(sig00000125)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000029a/blk0000029e  (
    .C(clk),
    .D(sig0000011c),
    .Q(sig00000126)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000029a/blk0000029d  (
    .C(clk),
    .D(sig0000011c),
    .Q(sig00000127)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000029a/blk0000029c  (
    .C(clk),
    .D(sig0000011c),
    .Q(sig00000128)
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk0000029a/blk0000029b  (
    .C(clk),
    .D(sig0000011d),
    .Q(sig00000129)
  );

// synthesis translate_on

endmodule

// synthesis translate_off

`ifndef GLBL
`define GLBL

`timescale  1 ps / 1 ps

module glbl ();

    parameter ROC_WIDTH = 100000;
    parameter TOC_WIDTH = 0;

//--------   STARTUP Globals --------------
    wire GSR;
    wire GTS;
    wire GWE;
    wire PRLD;
    tri1 p_up_tmp;
    tri (weak1, strong0) PLL_LOCKG = p_up_tmp;

    wire PROGB_GLBL;
    wire CCLKO_GLBL;

    reg GSR_int;
    reg GTS_int;
    reg PRLD_int;

//--------   JTAG Globals --------------
    wire JTAG_TDO_GLBL;
    wire JTAG_TCK_GLBL;
    wire JTAG_TDI_GLBL;
    wire JTAG_TMS_GLBL;
    wire JTAG_TRST_GLBL;

    reg JTAG_CAPTURE_GLBL;
    reg JTAG_RESET_GLBL;
    reg JTAG_SHIFT_GLBL;
    reg JTAG_UPDATE_GLBL;
    reg JTAG_RUNTEST_GLBL;

    reg JTAG_SEL1_GLBL = 0;
    reg JTAG_SEL2_GLBL = 0 ;
    reg JTAG_SEL3_GLBL = 0;
    reg JTAG_SEL4_GLBL = 0;

    reg JTAG_USER_TDO1_GLBL = 1'bz;
    reg JTAG_USER_TDO2_GLBL = 1'bz;
    reg JTAG_USER_TDO3_GLBL = 1'bz;
    reg JTAG_USER_TDO4_GLBL = 1'bz;

    assign (weak1, weak0) GSR = GSR_int;
    assign (weak1, weak0) GTS = GTS_int;
    assign (weak1, weak0) PRLD = PRLD_int;

    initial begin
	GSR_int = 1'b1;
	PRLD_int = 1'b1;
	#(ROC_WIDTH)
	GSR_int = 1'b0;
	PRLD_int = 1'b0;
    end

    initial begin
	GTS_int = 1'b1;
	#(TOC_WIDTH)
	GTS_int = 1'b0;
    end

endmodule

`endif

// synthesis translate_on
