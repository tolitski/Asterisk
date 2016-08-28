/*
 * xpmr_coef.h - for Xelatec Private Mobile Radio Processes
 * 
 * All Rights Reserved. Copyright (C)2007, Xelatec, LLC
 * 
 * 20070808 1235 Steven Henke, W9SH, sph@xelatec.com
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 * 		 
 * This version may be optionally licenced under the GNU LGPL licence.
 *
 * A license has been granted to Digium (via disclaimer) for the use of
 * this code.
 *
 * Some filter coeficients via 'WinFilter' http://www.winfilter.20m.com.
 *
 */

/*! \file
 *
 * \brief Private Land Mobile Radio Channel Voice and Signaling Processor
 *
 * \author Steven Henke, W9SH <sph@xelatec.com> Xelatec, LLC
 */

#ifndef XPMR_COEF_H
#define XMPR_COEF_H 	1

// frequencies in 0.1 Hz
static const u32 dtmf_row[] =
{
	6970,  7700,  8520,  9410
};
static const u32 dtmf_col[] =
{
	12090, 13360, 14770, 16330
};


#define CTCSS_COEF_INT		120
#define CTCSS_SAMPLE_RATE   8000
#define TDIV(x) ((CTCSS_SAMPLE_RATE*1000/x)+5)/10

#if 0
static i32 coef_ctcss[4][5]=
{
	// freq, divisor, integrator, filter
	{770,TDIV(770),CTCSS_COEF_INT,0,0},
	{1000,TDIV(1000),CTCSS_COEF_INT,0,0},
	{1035,TDIV(1035),CTCSS_COEF_INT,0,0},
	{0,0,0,0}
};
#endif

static i16 coef_ctcss_div[]=
{
2985,    // 00   067.0
2782,    // 01   071.9
2688,    // 02   074.4
2597,    // 03   077.0
2509,    // 04   079.7
2424,    // 05   082.5
2342,    // 06   085.4
2260,    // 07   088.5
2186,    // 08   091.5
2110,    // 09   094.8
2053,    // 10   097.4
2000,    // 11   100.0
1932,    // 12   103.5
1866,    // 13   107.2
1803,    // 14   110.9
1742,    // 15   114.8
1684,    // 16   118.8
1626,    // 17   123.0
1571,    // 18   127.3
1517,    // 19   131.8
1465,    // 20   136.5
1415,    // 21   141.3
1368,    // 22   146.2
1321,    // 23   151.4
1276,    // 24   156.7
1233,    // 25   162.2
1191,    // 26   167.9
1151,    // 27   173.8
1112,    // 28   179.9
1074,    // 29   186.2
1037,    // 30   192.8
983,    // 31   203.5
949,    // 32   210.7
917,    // 33   218.1
886,    // 34   225.7
856,    // 35   233.6
827,    // 36   241.8
799     // 37   250.3
};

static float freq_ctcss[]=
{
067.0,    // 00   
071.9,    // 01   
074.4,    // 02   
077.0,    // 03   
079.7,    // 04   
082.5,    // 05   
085.4,    // 06   
088.5,    // 07   
091.5,    // 08   
094.8,    // 09   
097.4,    // 10   
100.0,    // 11   
103.5,    // 12   
107.2,    // 13   
110.9,    // 14   
114.8,    // 15   
118.8,    // 16   
123.0,    // 17   
127.3,    // 18   
131.8,    // 19   
136.5,    // 20   
141.3,    // 21   
146.2,    // 22   
151.4,    // 23   
156.7,    // 24   
162.2,    // 25   
167.9,    // 26   
173.8,    // 27   
179.9,    // 28   
186.2,    // 29   
192.8,    // 30   
203.5,    // 31  
210.7 ,    // 32  
218.1 ,    // 33  
225.7 ,    // 34  
233.6 ,    // 35  
241.8 ,    // 36  
250.3      // 37  
};

/*
	noise squelch carrier detect filter
*/
static const int16_t taps_fir_bpf_noise_1 = 66;
static const int32_t gain_fir_bpf_noise_1 = 65536;
static const int16_t coef_fir_bpf_noise_1[] = { 
      139,
     -182,
     -269,
      -66,
       56,
       59,
      250,
      395,
      -80,
     -775,
     -557,
      437,
      779,
      210,
      -17,
      123,
     -692,
    -1664,
     -256,
     2495,
     2237,
    -1018,
    -2133,
     -478,
    -1134,
    -2711,
     2642,
    10453,
     4010,
    -14385,
    -16488,
     6954,
    23030,
     6954,
    -16488,
    -14385,
     4010,
    10453,
     2642,
    -2711,
    -1134,
     -478,
    -2133,
    -1018,
     2237,
     2495,
     -256,
    -1664,
     -692,
      123,
      -17,
      210,
      779,
      437,
     -557,
     -775,
      -80,
      395,
      250,
       59,
       56,
      -66,
     -269,
     -182,
      139,
      257
};

static const int16_t taps_fir_bpf_noise_2 = 66;
static const int32_t gain_fir_bpf_noise_2 = 65536;
static const int16_t coef_fir_bpf_noise_2[] = {
          581,
         -251,
        -1027,
         -766,
           63,
          346,
          148,
          459,
         1165,
          847,
         -824,
        -1994,
        -1147,
          462,
          704,
           32,
          651,
         2277,
         1790,
        -1635,
        -4071,
        -2240,
         1060,
         1127,
         -502,
         1963,
         7399,
         5862,
        -6693,
        -17483,
        -10387,
        10549,
        22110,
        10549,
        -10387,
        -17483,
        -6693,
         5862,
         7399,
         1963,
         -502,
         1127,
         1060,
        -2240,
        -4071,
        -1635,
         1790,
         2277,
          651,
           32,
          704,
          462,
        -1147,
        -1994,
         -824,
          847,
         1165,
          459,
          148,
          346,
           63,
         -766,
        -1027,
         -251,
          581,
          537
};

static const int16_t taps_fir_lpf_3K_2 = 28;
static const int32_t gain_fir_lpf_3K_2 = 65536;
static const int16_t coef_fir_lpf_3K_2[] = { 
   545,
  -329,
  -579,
   369,
  -843,
   465,
  -121,
  -779,
  1523,
 -2051,
  1683,
   -64,
 -4016,
 19793,
 19793,
 -4016,
   -64,
  1683,
 -2051,
  1523,
  -779,
  -121,
   465,
  -843,
   369,
  -579,
  -329,
   545

} ;

/**************************************************************
Filter type: Low Pass
Filter model: Butterworth
Filter order: 9
Sampling Frequency: 8 KHz
Cut Frequency: 0.250000 KHz
Coefficents Quantization: 16-bit
***************************************************************/
static const int16_t taps_fir_lpf_250_11_64 = 64;
static const int32_t gain_fir_lpf_250_11_64 = 262144;
static const int16_t coef_fir_lpf_250_11_64[] = 
{
      366,
       -3,
     -418,
     -865,
    -1328,
    -1788,
    -2223,
    -2609,
    -2922,
    -3138,
    -3232,
    -3181,
    -2967,
    -2573,
    -1988,
    -1206,
     -228,
      937,
     2277,
     3767,
     5379,
     7077,
     8821,
    10564,
    12259,
    13855,
    15305,
    16563,
    17588,
    18346,
    18812,
    18968,
    18812,
    18346,
    17588,
    16563,
    15305,
    13855,
    12259,
    10564,
     8821,
     7077,
     5379,
     3767,
     2277,
      937,
     -228,
    -1206,
    -1988,
    -2573,
    -2967,
    -3181,
    -3232,
    -3138,
    -2922,
    -2609,
    -2223,
    -1788,
    -1328,
     -865,
     -418,
       -3,
      366,
      680
};

// de-emphasis integrator 300 Hz with 8KS/s
// a0, b1
static const int16_t taps_int_lpf_300_1_2 = 2;
static const int32_t gain_int_lpf_300_1_2 = 8182;
static const int16_t coef_int_lpf_300_1_2[]={
6878,
25889
};

// pre-emphasis differentiator 4000 Hz with 8KS/s
// a0,a1,b0,
static const int16_t taps_int_hpf_4000_1_2 = 2;
//static const int32_t gain_int_hpf_4000_1_2 = 16384;  // per calculations
static const int32_t gain_int_hpf_4000_1_2 = 13404; // hand tweaked for unity gain at 1KHz
static const int16_t coef_int_hpf_4000_1_2[]={
17610,
-17610,
2454
};




/*
	ctcss decode filter
*/
/**************************************************************
Filter type: Low Pass
Filter model: Butterworth
Filter order: 9
Sampling Frequency: 8 KHz
Cut Frequency: 0.250000 KHz
Coefficents Quantization: 16-bit
***************************************************************/
static const int16_t taps_fir_lpf_250_9_66 = 66;
static const int32_t gain_fir_lpf_250_9_66 = 262144;
static const int16_t coef_fir_lpf_250_9_66[] = 
{ 
  676,
  364,
   -3,
 -415,
 -860,
-1320,
-1777,
-2209,
-2593,
-2904,
-3119,
-3212,
-3162,
-2949,
-2557,
-1975,
-1198,
 -226,
  932,
 2263,
 3744,
 5346,
 7034,
 8767,
10499,
12184,
13770,
15211,
16462,
17480,
18234,
18696,
18852,
18696,
18234,
17480,
16462,
15211,
13770,
12184,
10499,
 8767,
 7034,
 5346,
 3744,
 2263,
  932,
 -226,
-1198,
-1975,
-2557,
-2949,
-3162,
-3212,
-3119,
-2904,
-2593,
-2209,
-1777,
-1320,
 -860,
 -415,
   -3,
  364,
  676,
  927
};
/* *************************************************************
Filter type: Low Pass
Filter model: Butterworth
Filter order: 9
Sampling Frequency: 8 KHz
Cut Frequency: 0.215 KHz
Coefficents Quantization: 16-bit
***************************************************************/
static const int16_t taps_fir_lpf_215_9_88 = 88;
static const int32_t gain_fir_lpf_215_9_88 = 524288;
static const int16_t coef_fir_lpf_215_9_88[] = {
 2038,
 2049,
 1991,
 1859,
 1650,
 1363,
  999,
  562,
   58,
 -502,
-1106,
-1739,
-2382,
-3014,
-3612,
-4153,
-4610,
-4959,
-5172,
-5226,
-5098,
-4769,
-4222,
-3444,
-2430,
-1176,
  310,
 2021,
 3937,
 6035,
 8284,
10648,
13086,
15550,
17993,
20363,
22608,
24677,
26522,
28099,
29369,
30299,
30867,
31058,
30867,
30299,
29369,
28099,
26522,
24677,
22608,
20363,
17993,
15550,
13086,
10648,
 8284,
 6035,
 3937,
 2021,
  310,
-1176,
-2430,
-3444,
-4222,
-4769,
-5098,
-5226,
-5172,
-4959,
-4610,
-4153,
-3612,
-3014,
-2382,
-1739,
-1106,
 -502,
   58,
  562,
  999,
 1363,
 1650,
 1859,
 1991,
 2049,
 2038,
 1966
};
// end coef fir_lpf_215_9_88

////////////////////////////////////////////////////////////////////////
// Filter Tables
////////////////////////////////////////////////////////////////////////

#define MAX_COEFS 128

typedef struct t_fir {
    i16 taps;
    i32 gain;
    i16 coefs[MAX_COEFS];
} T_FIR;


static const T_FIR fir_rxlpf[] = {
    
    // Index 0 - 3 kHz corner
    {
        66, 131072,
        {259, 58, -185, -437, -654, -793, -815, -696, -434,
            -48, 414, 886, 1284, 1523, 1529, 1254, 691, -117, -1078,
            -2049, -2854, -3303, -3220, -2472, -995, 1187, 3952, 7086,
            10300, 13270, 15672, 17236, 17778, 17236, 15672, 13270,
            10300, 7086, 3952, 1187, -995, -2472, -3220, -3303, -2854,
            -2049, -1078, -117, 691, 1254, 1529, 1523, 1284, 886, 414,
            -48, -434, -696, -815, -793, -654, -437, -185, 58, 259, 393 }
    },
    
    // Index 1 -15th order Butterworth, 3.3 kHz corner
    {
        128, 131072,
        { 47, 83, 108, 114, 98, 61, 5, -58, -118, -163, -181,
            -165, -113, -32, 66, 164, 242, 282, 269, 200, 82, -68,
            -226, -358, -435, -434, -344, -171, 59, 310, 531, 674,
            697, 580, 325, -32, -436, -807, -1064, -1136, -979, -590,
            -15, 655, 1296, 1767, 1937, 1716, 1080, 83, -1133, -2356,
            -3325, -3772, -3469, -2270, -151, 2776, 6267, 9965, 13454,
            16317, 18195, 18849, 18195, 16317, 13454, 9965, 6267, 2776,
            -151, -2270, -3469, -3772, -3325, -2356, -1133, 83, 1080,
            1716, 1937, 1767, 1296, 655, -15, -590, -979, -1136, -1064,
            -807, -436, -32, 325, 580, 697, 674, 531, 310, 59, -171,
            -344, -434, -435, -358, -226, -68, 82, 200, 269, 282, 242,
            164, 66, -32, -113, -165, -181, -163, -118, -58, 5, 61, 98,
            114, 108, 83, 47, 6 }
    },
    
    // Index 2 - 17th order Butterworth, 3.7 kHz corner
    { 	128, 131072,
        { -43, -100, -140, -149, -122, -62, 21, 109, 181, 216, 201,
            135, 26, -102, -220, -298, -310, -246, -112, 66, 249, 392,
            453, 408, 254, 16, -253, -494, -638, -639, -477, -172, 214,
            597, 876, 967, 821, 444, -99, -693, -1190, -1448, -1366,
            -912, -148, 774, 1643, 2220, 2304, 1783, 678, -834, -2446,
            -3754, -4342, -3862, -2119, 869, 4855, 9381, 13852, 17631,
            20157, 21045, 20157, 17631, 13852, 9381, 4855, 869, -2119,
            -3862, -4342, -3754, -2446, -834, 678, 1783, 2304, 2220,
            1643, 774, -148, -912, -1366, -1448, -1190, -693, -99, 444,
            821, 967, 876, 597, 214, -172, -477, -639, -638, -494, -253,
            16, 254, 408, 453, 392, 249, 66, -112, -246, -310, -298,
            -220, -102, 26, 135, 201, 216, 181, 109, 21, -62, -122, -149,
            -140, -100, -43, 17 }
    }
};  // end of RX LPFís


static const T_FIR fir_rxhpf[] = {
    
    // Index 0 - 300 Hz HPF, Butterworth, 9th Order, 16 bit coefs
    {
        66, 32768,
        { -141, -114, -77, -30, 23, 83, 147, 210, 271, 324, 367, 396,
            407, 396, 362, 302, 216, 102, -36, -199, -383, -585, -798,
            -1017, -1237, -1452, -1653, -1836, -1995, -2124, -2219,
            -2278, 30463, -2278, -2219, -2124, -1995, -1836, -1653,
            -1452, -1237, -1017, -798, -585, -383, -199, -36, 102, 216,
            302, 362, 396, 407, 396, 367, 324, 271, 210, 147, 83, 23,
            -30, -77, -114, -141, -158 }
    },
    
    // Index 1 - 250 Hz HPF, 9th order Butterworth
    {
        128, 32768,
        { 32, 39, 45, 50, 53, 54, 54, 51, 45, 37, 27, 15, 0, -15,
            -32, -50, -68, -85, -100, -114, -124, -130, -132, -129,
            -121, -107, -87, -61, -31, 4, 43, 85, 128, 171, 213, 251,
            284, 310, 328, 334, 329, 310, 276, 228, 164, 84, -9, -118,
            -240, -372, -514, -663, -815, -968, -1119, -1265, -1403,
            -1529, -1641, -1737, -1813, -1869, -1904, 30856, -1904,
            -1869, -1813, -1737, -1641, -1529, -1403, -1265, -1119,
            -968, -815, -663, -514, -372, -240, -118, -9, 84, 164, 228,
            276, 310, 329, 334, 328, 310, 284, 251, 213, 171, 128, 85,
            43, 4, -31, -61, -87, -107, -121, -129, -132, -130, -124,
            -114, -100, -85, -68, -50, -32, -15, 0, 15, 27, 37, 45, 51,
            54, 54, 53, 50, 45, 39, 32, 25 }
    }
};  // end of RX HPFís


static const T_FIR fir_txhpf[] = {
    
    // Index 0 - 300 Hz HPF
    {
        66, 32768,
        { -141, -114, -77, -30, 23, 83, 147, 210, 271, 324, 367, 396,
            407, 396, 362, 302, 216, 102, -36, -199, -383, -585, -798,
            -1017, -1237, -1452, -1653, -1836, -1995, -2124, -2219,
            -2278, 30463, -2278, -2219, -2124, -1995, -1836, -1653,
            -1452, -1237, -1017, -798, -585, -383, -199, -36, 102, 216,
            302, 362, 396, 407, 396, 367, 324, 271, 210, 147, 83, 23,
            -30, -77, -114, -141, -158 }
    },
    
    // Index 1 - 250 Hz HPF, 7th order Butterworth
    {
        96, 32768,
        { -56, -68, -79, -88, -95, -99, -99, -95, -87, -74, -57,
            -35, -9, 20, 53, 89, 125, 162, 197, 229, 257, 279, 292,
            296, 289, 270, 238, 191, 130, 54, -35, -139, -256, -383,
            -519, -662, -810, -958, -1105, -1248, -1382, -1505, -1615,
            -1709, -1784, -1840, -1873, 30876, -1873, -1840, -1784,
            -1709, -1615, -1505, -1382, -1248, -1105, -958, -810, -662,
            -519, -383, -256, -139, -35, 54, 130, 191, 238, 270, 289,
            296, 292, 279, 257, 229, 197, 162, 125, 89, 53, 20, -9, -35,
            -57, -74, -87, -95, -99, -99, -95, -88, -79, -68, -56, -44 }
    },
    
    // Index 2 - 120 Hz HPF, 5th order Butterworth
    {
        128, 32768,
        { 48, 53, 58, 63, 67, 72, 76, 80, 84, 87, 89, 91, 92, 93,
            92, 91, 88, 85, 80, 74, 67, 58, 48, 37, 24, 10, -5, -22,
            -41, -61, -82, -105, -130, -156, -183, -211, -240, -270,
            -301, -332, -365, -397, -430, -463, -496, -528, -561, -592,
            -623, -653, -681, -709, -734, -759, -781, -802, -820, -836,
            -850, -861, -871, -877, -881, 31887, -881, -877, -871, -861,
            -850, -836, -820, -802, -781, -759, -734, -709, -681, -653,
            -623, -592, -561, -528, -496, -463, -430, -397, -365, -332,
            -301, -270, -240, -211, -183, -156, -130, -105, -82, -61,
            -41, -22, -5, 10, 24, 37, 48, 58, 67, 74, 80, 85, 88, 91, 92,
            93, 92, 91, 89, 87, 84, 80, 76, 72, 67, 63, 58, 53, 48, 43 }
    }
    
};  // end of TX HPFís


static const T_FIR fir_txlpf[] = {
    
    // Index 0 - 3 kHz LPF
    {
        66, 131072,
        {259, 58, -185, -437, -654, -793, -815, -696, -434,
            -48, 414, 886, 1284, 1523, 1529, 1254, 691, -117, -1078,
            -2049, -2854, -3303, -3220, -2472, -995, 1187, 3952, 7086,
            10300, 13270, 15672, 17236, 17778, 17236, 15672, 13270,
            10300, 7086, 3952, 1187, -995, -2472, -3220, -3303, -2854,
            -2049, -1078, -117, 691, 1254, 1529, 1523, 1284, 886, 414,
            -48, -434, -696, -815, -793, -654, -437, -185, 58, 259, 393 }
    },
    
    // Index 1 - 3.3 kHz LPF, 15th order Butterworth
    { 
        128, 131072,
        { 47, 83, 108, 114, 98, 61, 5, -58, -118, -163, -181, 
            -165, -113, -32, 66, 164, 242, 282, 269, 200, 82, -68, 
            -226, -358, -435, -434, -344, -171, 59, 310, 531, 674, 
            697, 580, 325, -32, -436, -807, -1064, -1136, -979, -590, 
            -15, 655, 1296, 1767, 1937, 1716, 1080, 83, -1133, -2356,
            -3325, -3772, -3469, -2270, -151, 2776, 6267, 9965, 13454,
            16317, 18195, 18849, 18195, 16317, 13454, 9965, 6267, 2776, 
            -151, -2270, -3469, -3772, -3325, -2356, -1133, 83, 1080,
            1716, 1937, 1767, 1296, 655, -15, -590, -979, -1136, -1064,
            -807, -436, -32, 325, 580, 697, 674, 531, 310, 59, -171,
            -344, -434, -435, -358, -226, -68, 82, 200, 269, 282, 242,
            164, 66, -32, -113, -165, -181, -163, -118, -58, 5, 61, 98,
            114, 108, 83, 47, 6 }
    }
    
};  // end of TX LPFís

#define MAX_RXLPF (sizeof(fir_rxlpf) / sizeof(T_FIR))
#define MAX_RXHPF (sizeof(fir_rxhpf) / sizeof(T_FIR))
#define MAX_TXHPF (sizeof(fir_txhpf) / sizeof(T_FIR))
#define MAX_TXLPF (sizeof(fir_txlpf) / sizeof(T_FIR))


#endif /* !XPMR_COEF_H */
/* end of file */




