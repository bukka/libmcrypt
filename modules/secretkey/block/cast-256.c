/* This is an independent implementation of the encryption algorithm:   */
/*                                                                      */
/*         CAST-256 by Carlisle Adams of Entrust Tecnhologies           */
/*                                                                      */
/* which is a candidate algorithm in the Advanced Encryption Standard   */
/* programme of the US National Institute of Standards and Technology.  */
/*                                                                      */
/* Copyright in this implementation is held by Dr B R Gladman but I     */
/* hereby give permission for its free direct or derivative use subject */
/* to acknowledgment of its origin and compliance with any conditions   */
/* that the originators of the algorithm place on its exploitation.     */
/*                                                                      */
/* Dr Brian Gladman (gladman@seven77.demon.co.uk) 14th January 1999     */

/* modified in order to use the libmcrypt API by Nikos Mavroyanopoulos 
 * All modifications are placed under the license of libmcrypt.
 */

/* $Id$ */

/* modified for mcrypt */

/* Timing data for CAST-256 (cast.c)

Core timing without I/O endian conversion:

128 bit key:
Key Setup:    4333 cycles
Encrypt:       633 cycles =    40.4 mbits/sec
Decrypt:       634 cycles =    40.4 mbits/sec
Mean:          634 cycles =    40.4 mbits/sec

192 bit key:
Key Setup:    4342 cycles
Encrypt:       633 cycles =    40.4 mbits/sec
Decrypt:       633 cycles =    40.4 mbits/sec
Mean:          633 cycles =    40.4 mbits/sec

256 bit key:
Key Setup:    4325 cycles
Encrypt:       639 cycles =    40.1 mbits/sec
Decrypt:       638 cycles =    40.1 mbits/sec
Mean:          639 cycles =    40.1 mbits/sec

Full timing with I/O endian conversion:

128 bit key:
Key Setup:    4294 cycles
Encrypt:       678 cycles =    37.8 mbits/sec
Decrypt:       669 cycles =    38.3 mbits/sec
Mean:          674 cycles =    38.0 mbits/sec

192 bit key:
Key Setup:    4314 cycles
Encrypt:       678 cycles =    37.8 mbits/sec
Decrypt:       670 cycles =    38.2 mbits/sec
Mean:          674 cycles =    38.0 mbits/sec

256 bit key:
Key Setup:    4313 cycles
Encrypt:       678 cycles =    37.8 mbits/sec
Decrypt:       669 cycles =    38.3 mbits/sec
Mean:          674 cycles =    38.0 mbits/sec

*/

#include <mcrypt_common_inc.h>
#include "cast-256.h"

#define _mcrypt_set_key cast_256_LTX__mcrypt_set_key
#define _mcrypt_encrypt cast_256_LTX__mcrypt_encrypt
#define _mcrypt_decrypt cast_256_LTX__mcrypt_decrypt
#define _mcrypt_get_size cast_256_LTX__mcrypt_get_size
#define _mcrypt_get_block_size cast_256_LTX__mcrypt_get_block_size
#define _is_block_algorithm cast_256_LTX__is_block_algorithm
#define _mcrypt_get_key_size cast_256_LTX__mcrypt_get_key_size
#define _mcrypt_get_supported_key_sizes cast_256_LTX__mcrypt_get_supported_key_sizes
#define _mcrypt_get_algorithms_name cast_256_LTX__mcrypt_get_algorithms_name
#define _mcrypt_self_test cast_256_LTX__mcrypt_self_test
#define _mcrypt_algorithm_version cast_256_LTX__mcrypt_algorithm_version

#define byte(x,n)   ((byte)((x) >> (8 * n)))

word32 cast256_sbox[4][256] = { {
				 0x30fb40d4, 0x9fa0ff0b, 0x6beccd2f,
				 0x3f258c7a, 0x1e213f2f, 0x9C004dd3,
				 0x6003e540, 0xcf9fc949, 0xbfd4af27,
				 0x88bbbdb5, 0xe2034090, 0x98d09675,
				 0x6e63a0e0, 0x15c361d2, 0xc2e7661d,
				 0x22d4ff8e, 0x28683b6f, 0xc07fd059,
				 0xff2379c8, 0x775f50e2, 0x43c340d3,
				 0xdf2f8656, 0x887ca41a, 0xa2d2bd2d,
				 0xa1c9e0d6, 0x346c4819, 0x61b76d87,
				 0x22540f2f, 0x2abe32e1, 0xaa54166b,
				 0x22568e3a, 0xa2d341d0, 0x66db40c8,
				 0xa784392f, 0x004dff2f, 0x2db9d2de,
				 0x97943fac, 0x4a97c1d8, 0x527644b7,
				 0xb5f437a7, 0xb82cbaef, 0xd751d159,
				 0x6ff7f0ed, 0x5a097a1f, 0x827b68d0,
				 0x90ecf52e, 0x22b0c054, 0xbc8e5935,
				 0x4b6d2f7f, 0x50bb64a2, 0xd2664910,
				 0xbee5812d, 0xb7332290, 0xe93b159f,
				 0xb48ee411, 0x4bff345d, 0xfd45c240,
				 0xad31973f, 0xc4f6d02e, 0x55fc8165,
				 0xd5b1caad, 0xa1ac2dae, 0xa2d4b76d,
				 0xc19b0C50, 0x882240f2, 0x0c6e4f38,
				 0xa4e4bfd7, 0x4f5ba272, 0x564c1d2f,
				 0xc59c5319, 0xb949e354, 0xb04669fe,
				 0xb1b6ab8a, 0xc71358dd, 0x6385c545,
				 0x110f935d, 0x57538ad5, 0x6a390493,
				 0xe63d37e0, 0x2a54f6b3, 0x3a787d5f,
				 0x6276a0b5, 0x19a6fcdf, 0x7a42206a,
				 0x29f9d4d5, 0xf61b1891, 0xbb72275e,
				 0xaa508167, 0x38901091, 0xc6b505eb,
				 0x84c7cb8c, 0x2ad75a0f, 0x874a1427,
				 0xa2d1936b, 0x2ad286af, 0xaa56d291,
				 0xd7894360, 0x425c750d, 0x93b39e26,
				 0x187184c9, 0x6c00b32d, 0x73e2bb14,
				 0xa0bebc3c, 0x54623779, 0x64459eab,
				 0x3f328b82, 0x7718cf82, 0x59a2cea6,
				 0x04ee002e, 0x89fe78e6, 0x3fab0950,
				 0x325ff6C2, 0x81383f05, 0x6963c5c8,
				 0x76cb5ad6, 0xd49974c9, 0xca180dcf,
				 0x380782d5, 0xc7fa5cf6, 0x8ac31511,
				 0x35e79e13, 0x47da91d0, 0xf40f9086,
				 0xa7e2419e, 0x31366241, 0x051ef495,
				 0xaa573b04, 0x4a805d8d, 0x548300d0,
				 0x00322a3c, 0xbf64cddf, 0xba57a68e,
				 0x75c6372b, 0x50afd341, 0xa7c13275,
				 0x915a0bf5, 0x6b54bfab, 0x2b0b1426,
				 0xab4cc9d7, 0x449ccd82, 0xf7fbf265,
				 0xab85c5f3, 0x1b55db94, 0xaad4e324,
				 0xcfa4bd3f, 0x2deaa3e2, 0x9e204d02,
				 0xc8bd25ac, 0xeadf55b3, 0xd5bd9e98,
				 0xe31231b2, 0x2ad5ad6c, 0x954329de,
				 0xadbe4528, 0xd8710f69, 0xaa51c90f,
				 0xaa786bf6, 0x22513f1e, 0xaa51a79b,
				 0x2ad344cc, 0x7b5a41f0, 0xd37cfbad,
				 0x1b069505, 0x41ece491, 0xb4c332e6,
				 0x032268d4, 0xc9600acc, 0xce387e6d,
				 0xbf6bb16c, 0x6a70fb78, 0x0d03d9c9,
				 0xd4df39de, 0xe01063da, 0x4736f464,
				 0x5ad328d8, 0xb347cc96, 0x75bb0fc3,
				 0x98511bfb, 0x4ffbcc35, 0xb58bcf6a,
				 0xe11f0abc, 0xbfc5fe4a, 0xa70aec10,
				 0xac39570a, 0x3f04442f, 0x6188b153,
				 0xe0397a2e, 0x5727cb79, 0x9ceb418f,
				 0x1cacd68d, 0x2ad37c96, 0x0175cb9d,
				 0xc69dff09, 0xc75b65f0, 0xd9db40d8,
				 0xec0e7779, 0x4744ead4, 0xb11c3274,
				 0xdd24cb9e, 0x7e1c54bd, 0xf01144f9,
				 0xd2240eb1, 0x9675b3fd, 0xa3ac3755,
				 0xd47c27af, 0x51c85f4d, 0x56907596,
				 0xa5bb15e6, 0x580304f0, 0xca042cf1,
				 0x011a37ea, 0x8dbfaadb, 0x35ba3e4a,
				 0x3526ffa0, 0xc37b4d09, 0xbc306ed9,
				 0x98a52666, 0x5648f725, 0xff5e569d,
				 0x0ced63d0, 0x7c63b2cf, 0x700b45e1,
				 0xd5ea50f1, 0x85a92872, 0xaf1fbda7,
				 0xd4234870, 0xa7870bf3, 0x2d3b4d79,
				 0x42e04198, 0x0cd0ede7, 0x26470db8,
				 0xf881814C, 0x474d6ad7, 0x7c0c5e5c,
				 0xd1231959, 0x381b7298, 0xf5d2f4db,
				 0xab838653, 0x6e2f1e23, 0x83719c9e,
				 0xbd91e046, 0x9a56456e, 0xdc39200c,
				 0x20c8c571, 0x962bda1c, 0xe1e696ff,
				 0xb141ab08, 0x7cca89b9, 0x1a69e783,
				 0x02cc4843, 0xa2f7c579, 0x429ef47d,
				 0x427b169c, 0x5ac9f049, 0xdd8f0f00,
				 0x5c8165bf}
,
{
 0x1f201094, 0xef0ba75b, 0x69e3cf7e, 0x393f4380, 0xfe61cf7a, 0xeec5207a,
 0x55889c94, 0x72fc0651, 0xada7ef79, 0x4e1d7235, 0xd55a63ce, 0xde0436ba,
 0x99c430ef, 0x5f0c0794, 0x18dcdb7d, 0xa1d6eff3, 0xa0b52f7b, 0x59e83605,
 0xee15b094, 0xe9ffd909, 0xdc440086, 0xef944459, 0xba83ccb3, 0xe0c3cdfb,
 0xd1da4181, 0x3b092ab1, 0xf997f1c1, 0xa5e6cf7b, 0x01420ddb, 0xe4e7ef5b,
 0x25a1ff41, 0xe180f806, 0x1fc41080, 0x179bee7a, 0xd37ac6a9, 0xfe5830a4,
 0x98de8b7f, 0x77e83f4e, 0x79929269, 0x24fa9f7b, 0xe113c85b, 0xacc40083,
 0xd7503525, 0xf7ea615f, 0x62143154, 0x0d554b63, 0x5d681121, 0xc866c359,
 0x3d63cf73, 0xcee234c0, 0xd4d87e87, 0x5c672b21, 0x071f6181, 0x39f7627f,
 0x361e3084, 0xe4eb573b, 0x602f64a4, 0xd63acd9c, 0x1bbc4635, 0x9e81032d,
 0x2701f50c, 0x99847ab4, 0xa0e3df79, 0xba6cf38c, 0x10843094, 0x2537a95e,
 0xf46f6ffe, 0xa1ff3b1f, 0x208cfb6a, 0x8f458c74, 0xd9e0a227, 0x4ec73a34,
 0xfc884f69, 0x3e4de8df, 0xef0e0088, 0x3559648d, 0x8a45388c, 0x1d804366,
 0x721d9bfd, 0xa58684bb, 0xe8256333, 0x844e8212, 0x128d8098, 0xfed33fb4,
 0xce280ae1, 0x27e19ba5, 0xd5a6c252, 0xe49754bd, 0xc5d655dd, 0xeb667064,
 0x77840b4d, 0xa1b6a801, 0x84db26a9, 0xe0b56714, 0x21f043b7, 0xe5d05860,
 0x54f03084, 0x066ff472, 0xa31aa153, 0xdadc4755, 0xb5625dbf, 0x68561be6,
 0x83ca6b94, 0x2d6ed23b, 0xeccf01db, 0xa6d3d0ba, 0xb6803d5c, 0xaf77a709,
 0x33b4a34c, 0x397bc8d6, 0x5ee22b95, 0x5f0e5304, 0x81ed6f61, 0x20e74364,
 0xb45e1378, 0xde18639b, 0x881ca122, 0xb96726d1, 0x8049a7e8, 0x22b7da7b,
 0x5e552d25, 0x5272d237, 0x79d2951c, 0xc60d894c, 0x488cb402, 0x1ba4fe5b,
 0xa4b09f6b, 0x1ca815cf, 0xa20c3005, 0x8871df63, 0xb9de2fcb, 0x0cc6c9e9,
 0x0beeff53, 0xe3214517, 0xb4542835, 0x9f63293c, 0xee41e729, 0x6e1d2d7c,
 0x50045286, 0x1e6685f3, 0xf33401c6, 0x30a22c95, 0x31a70850, 0x60930f13,
 0x73f98417, 0xa1269859, 0xec645c44, 0x52c877a9, 0xcdff33a6, 0xa02b1741,
 0x7cbad9a2, 0x2180036f, 0x50d99c08, 0xcb3f4861, 0xc26bd765, 0x64a3f6ab,
 0x80342676, 0x25a75e7b, 0xe4e6d1fc, 0x20c710e6, 0xcdf0b680, 0x17844d3b,
 0x31eef84d, 0x7e0824e4, 0x2ccb49eb, 0x846a3bae, 0x8ff77888, 0xee5d60f6,
 0x7af75673, 0x2fdd5cdb, 0xa11631c1, 0x30f66f43, 0xb3faec54, 0x157fd7fa,
 0xef8579cc, 0xd152de58, 0xdb2ffd5e, 0x8f32ce19, 0x306af97a, 0x02f03ef8,
 0x99319ad5, 0xc242fa0f, 0xa7e3ebb0, 0xc68e4906, 0xb8da230c, 0x80823028,
 0xdcdef3c8, 0xd35fb171, 0x088a1bc8, 0xbec0c560, 0x61a3c9e8, 0xbca8f54d,
 0xc72feffa, 0x22822e99, 0x82c570b4, 0xd8d94e89, 0x8b1c34bc, 0x301e16e6,
 0x273be979, 0xb0ffeaa6, 0x61d9b8c6, 0x00b24869, 0xb7ffce3f, 0x08dc283b,
 0x43daf65a, 0xf7e19798, 0x7619b72f, 0x8f1c9ba4, 0xdc8637a0, 0x16a7d3b1,
 0x9fc393b7, 0xa7136eeb, 0xc6bcc63e, 0x1a513742, 0xef6828bc, 0x520365d6,
 0x2d6a77ab, 0x3527ed4b, 0x821fd216, 0x095c6e2e, 0xdb92f2fb, 0x5eea29cb,
 0x145892f5, 0x91584f7f, 0x5483697b, 0x2667a8cc, 0x85196048, 0x8c4bacea,
 0x833860d4, 0x0d23e0f9, 0x6c387e8a, 0x0ae6d249, 0xb284600c, 0xd835731d,
 0xdcb1c647, 0xac4c56ea, 0x3ebd81b3, 0x230eabb0, 0x6438bc87, 0xf0b5b1fa,
 0x8f5ea2b3, 0xfc184642, 0x0a036b7a, 0x4fb089bd, 0x649da589, 0xa345415e,
 0x5c038323, 0x3e5d3bb9, 0x43d79572, 0x7e6dd07c, 0x06dfdf1e, 0x6c6cc4ef,
 0x7160a539, 0x73bfbe70, 0x83877605, 0x4523ecf1}
,
{
 0x8defc240, 0x25fa5d9f, 0xeb903dbf, 0xe810c907, 0x47607fff, 0x369fe44b,
 0x8c1fc644, 0xaececa90, 0xbeb1f9bf, 0xeefbcaea, 0xe8cf1950, 0x51df07ae,
 0x920e8806, 0xf0ad0548, 0xe13c8d83, 0x927010d5, 0x11107d9f, 0x07647db9,
 0xb2e3e4d4, 0x3d4f285e, 0xb9afa820, 0xfade82e0, 0xa067268b, 0x8272792e,
 0x553fb2c0, 0x489ae22b, 0xd4ef9794, 0x125e3fbc, 0x21fffcee, 0x825b1bfd,
 0x9255c5ed, 0x1257a240, 0x4e1a8302, 0xbae07fff, 0x528246e7, 0x8e57140e,
 0x3373f7bf, 0x8c9f8188, 0xa6fc4ee8, 0xc982b5a5, 0xa8c01db7, 0x579fc264,
 0x67094f31, 0xf2bd3f5f, 0x40fff7c1, 0x1fb78dfc, 0x8e6bd2c1, 0x437be59b,
 0x99b03dbf, 0xb5dbc64b, 0x638dc0e6, 0x55819d99, 0xa197c81c, 0x4a012d6e,
 0xc5884a28, 0xccc36f71, 0xb843c213, 0x6c0743f1, 0x8309893c, 0x0feddd5f,
 0x2f7fe850, 0xd7c07f7e, 0x02507fbf, 0x5afb9a04, 0xa747d2d0, 0x1651192e,
 0xaf70bf3e, 0x58c31380, 0x5f98302e, 0x727cc3c4, 0x0a0fb402, 0x0f7fef82,
 0x8c96fdad, 0x5d2c2aae, 0x8ee99a49, 0x50da88b8, 0x8427f4a0, 0x1eac5790,
 0x796fb449, 0x8252dc15, 0xefbd7d9b, 0xa672597d, 0xada840d8, 0x45f54504,
 0xfa5d7403, 0xe83ec305, 0x4f91751a, 0x925669c2, 0x23efe941, 0xa903f12e,
 0x60270df2, 0x0276e4b6, 0x94fd6574, 0x927985b2, 0x8276dbcb, 0x02778176,
 0xf8af918d, 0x4e48f79e, 0x8f616ddf, 0xe29d840e, 0x842f7d83, 0x340ce5c8,
 0x96bbb682, 0x93b4b148, 0xef303cab, 0x984faf28, 0x779faf9b, 0x92dc560d,
 0x224d1e20, 0x8437aa88, 0x7d29dc96, 0x2756d3dc, 0x8b907cee, 0xb51fd240,
 0xe7c07ce3, 0xe566b4a1, 0xc3e9615e, 0x3cf8209d, 0x6094d1e3, 0xcd9ca341,
 0x5c76460e, 0x00ea983b, 0xd4d67881, 0xfd47572c, 0xf76cedd9, 0xbda8229c,
 0x127dadaa, 0x438a074e, 0x1f97c090, 0x081bdb8a, 0x93a07ebe, 0xb938ca15,
 0x97b03cff, 0x3dc2c0f8, 0x8d1ab2ec, 0x64380e51, 0x68cc7bfb, 0xd90f2788,
 0x12490181, 0x5de5ffd4, 0xdd7ef86a, 0x76a2e214, 0xb9a40368, 0x925d958f,
 0x4b39fffa, 0xba39aee9, 0xa4ffd30b, 0xfaf7933b, 0x6d498623, 0x193cbcfa,
 0x27627545, 0x825cf47a, 0x61bd8ba0, 0xd11e42d1, 0xcead04f4, 0x127ea392,
 0x10428db7, 0x8272a972, 0x9270c4a8, 0x127de50b, 0x285ba1c8, 0x3c62f44f,
 0x35c0eaa5, 0xe805d231, 0x428929fb, 0xb4fcdf82, 0x4fb66a53, 0x0e7dc15b,
 0x1f081fab, 0x108618ae, 0xfcfd086d, 0xf9ff2889, 0x694bcc11, 0x236a5cae,
 0x12deca4d, 0x2c3f8cc5, 0xd2d02dfe, 0xf8ef5896, 0xe4cf52da, 0x95155b67,
 0x494a488c, 0xb9b6a80c, 0x5c8f82bc, 0x89d36b45, 0x3a609437, 0xec00c9a9,
 0x44715253, 0x0a874b49, 0xd773bc40, 0x7c34671c, 0x02717ef6, 0x4feb5536,
 0xa2d02fff, 0xd2bf60c4, 0xd43f03c0, 0x50b4ef6d, 0x07478cd1, 0x006e1888,
 0xa2e53f55, 0xb9e6d4bc, 0xa2048016, 0x97573833, 0xd7207d67, 0xde0f8f3d,
 0x72f87b33, 0xabcc4f33, 0x7688c55d, 0x7b00a6b0, 0x947b0001, 0x570075d2,
 0xf9bb88f8, 0x8942019e, 0x4264a5ff, 0x856302e0, 0x72dbd92b, 0xee971b69,
 0x6ea22fde, 0x5f08ae2b, 0xaf7a616d, 0xe5c98767, 0xcf1febd2, 0x61efc8c2,
 0xf1ac2571, 0xcc8239c2, 0x67214cb8, 0xb1e583d1, 0xb7dc3e62, 0x7f10bdce,
 0xf90a5c38, 0x0ff0443d, 0x606e6dc6, 0x60543a49, 0x5727c148, 0x2be98a1d,
 0x8ab41738, 0x20e1be24, 0xaf96da0f, 0x68458425, 0x99833be5, 0x600d457d,
 0x282f9350, 0x8334b362, 0xd91d1120, 0x2b6d8da0, 0x642b1e31, 0x9c305a00,
 0x52bce688, 0x1b03588a, 0xf7baefd5, 0x4142ed9c, 0xa4315c11, 0x83323ec5,
 0xdfef4636, 0xa133c501, 0xe9d3531c, 0xee353783}
,
{
 0x9db30420, 0x1fb6e9de, 0xa7be7bef, 0xd273a298, 0x4a4f7bdb, 0x64ad8c57,
 0x85510443, 0xfa020ed1, 0x7e287aff, 0xe60fb663, 0x095f35a1, 0x79ebf120,
 0xfd059d43, 0x6497b7b1, 0xf3641f63, 0x241e4adf, 0x28147f5f, 0x4fa2b8cd,
 0xc9430040, 0x0cc32220, 0xfdd30b30, 0xc0a5374f, 0x1d2d00d9, 0x24147b15,
 0xee4d111a, 0x0fca5167, 0x71ff904c, 0x2d195ffe, 0x1a05645f, 0x0c13fefe,
 0x081b08ca, 0x05170121, 0x80530100, 0xe83e5efe, 0xac9af4f8, 0x7fe72701,
 0xd2b8ee5f, 0x06df4261, 0xbb9e9b8a, 0x7293ea25, 0xce84ffdf, 0xf5718801,
 0x3dd64b04, 0xa26f263b, 0x7ed48400, 0x547eebe6, 0x446d4ca0, 0x6cf3d6f5,
 0x2649abdf, 0xaea0c7f5, 0x36338cc1, 0x503f7e93, 0xd3772061, 0x11b638e1,
 0x72500e03, 0xf80eb2bb, 0xabe0502e, 0xec8d77de, 0x57971e81, 0xe14f6746,
 0xc9335400, 0x6920318f, 0x081dbb99, 0xffc304a5, 0x4d351805, 0x7f3d5ce3,
 0xa6c866c6, 0x5d5bcca9, 0xdaec6fea, 0x9f926f91, 0x9f46222f, 0x3991467d,
 0xa5bf6d8e, 0x1143c44f, 0x43958302, 0xd0214eeb, 0x022083b8, 0x3fb6180c,
 0x18f8931e, 0x281658e6, 0x26486e3e, 0x8bd78a70, 0x7477e4c1, 0xb506e07c,
 0xf32d0a25, 0x79098b02, 0xe4eabb81, 0x28123b23, 0x69dead38, 0x1574ca16,
 0xdf871b62, 0x211c40b7, 0xa51a9ef9, 0x0014377b, 0x041e8ac8, 0x09114003,
 0xbd59e4d2, 0xe3d156d5, 0x4fe876d5, 0x2f91a340, 0x557be8de, 0x00eae4a7,
 0x0ce5c2ec, 0x4db4bba6, 0xe756bdff, 0xdd3369ac, 0xec17b035, 0x06572327,
 0x99afc8b0, 0x56c8c391, 0x6b65811c, 0x5e146119, 0x6e85cb75, 0xbe07c002,
 0xc2325577, 0x893ff4ec, 0x5bbfc92d, 0xd0ec3b25, 0xb7801ab7, 0x8d6d3b24,
 0x20c763ef, 0xc366a5fc, 0x9c382880, 0x0ace3205, 0xaac9548a, 0xeca1d7c7,
 0x041afa32, 0x1d16625a, 0x6701902c, 0x9b757a54, 0x31d477f7, 0x9126b031,
 0x36cc6fdb, 0xc70b8b46, 0xd9e66a48, 0x56e55a79, 0x026a4ceb, 0x52437eff,
 0x2f8f76b4, 0x0df980a5, 0x8674cde3, 0xedda04eb, 0x17a9be04, 0x2c18f4df,
 0xb7747f9d, 0xab2af7b4, 0xefc34d20, 0x2e096b7c, 0x1741a254, 0xe5b6a035,
 0x213d42f6, 0x2c1c7c26, 0x61c2f50f, 0x6552daf9, 0xd2c231f8, 0x25130f69,
 0xd8167fa2, 0x0418f2c8, 0x001a96a6, 0x0d1526ab, 0x63315c21, 0x5e0a72ec,
 0x49bafefd, 0x187908d9, 0x8d0dbd86, 0x311170a7, 0x3e9b640c, 0xcc3e10d7,
 0xd5cad3b6, 0x0caec388, 0xf73001e1, 0x6c728aff, 0x71eae2a1, 0x1f9af36e,
 0xcfcbd12f, 0xc1de8417, 0xac07be6b, 0xcb44a1d8, 0x8b9b0f56, 0x013988c3,
 0xb1c52fca, 0xb4be31cd, 0xd8782806, 0x12a3a4e2, 0x6f7de532, 0x58fd7eb6,
 0xd01ee900, 0x24adffc2, 0xf4990fc5, 0x9711aac5, 0x001d7b95, 0x82e5e7d2,
 0x109873f6, 0x00613096, 0xc32d9521, 0xada121ff, 0x29908415, 0x7fbb977f,
 0xaf9eb3db, 0x29c9ed2a, 0x5ce2a465, 0xa730f32c, 0xd0aa3fe8, 0x8a5cc091,
 0xd49e2ce7, 0x0ce454a9, 0xd60acd86, 0x015f1919, 0x77079103, 0xdea03af6,
 0x78a8565e, 0xdee356df, 0x21f05cbe, 0x8b75e387, 0xb3c50651, 0xb8a5c3ef,
 0xd8eeb6d2, 0xe523be77, 0xc2154529, 0x2f69efdf, 0xafe67afb, 0xf470c4b2,
 0xf3e0eb5b, 0xd6cc9876, 0x39e4460c, 0x1fda8538, 0x1987832f, 0xca007367,
 0xa99144f8, 0x296b299e, 0x492fc295, 0x9266beab, 0xb5676e69, 0x9bd3ddda,
 0xdf7e052f, 0xdb25701c, 0x1b5e51ee, 0xf65324e6, 0x6afce36c, 0x0316cc04,
 0x8644213e, 0xb7dc59d0, 0x7965291f, 0xccd6fd43, 0x41823979, 0x932bcdf6,
 0xb657c34d, 0x4edfd282, 0x7ae5290c, 0x3cb9536b, 0x851e20fe, 0x9833557e,
 0x13ecf0b0, 0xd3ffb372, 0x3f85c5c1, 0x0aef7ed2}
};


#define f1(y,x,kr,km)           \
    t  = rotl32(km + x, kr);      \
    u  = cast256_sbox[0][byte(t,3)];   \
    u ^= cast256_sbox[1][byte(t,2)];   \
    u -= cast256_sbox[2][byte(t,1)];   \
    u += cast256_sbox[3][byte(t,0)];   \
    y ^= u

#define f2(y,x,kr,km)           \
    t  = rotl32(km ^ x, kr);      \
    u  = cast256_sbox[0][byte(t,3)];   \
    u -= cast256_sbox[1][byte(t,2)];   \
    u += cast256_sbox[2][byte(t,1)];   \
    u ^= cast256_sbox[3][byte(t,0)];   \
    y ^= u

#define f3(y,x,kr,km)           \
    t  = rotl32(km - x, kr);      \
    u  = cast256_sbox[0][byte(t,3)];   \
    u += cast256_sbox[1][byte(t,2)];   \
    u ^= cast256_sbox[2][byte(t,1)];   \
    u -= cast256_sbox[3][byte(t,0)];   \
    y ^= u

#define f_rnd(x,n)                              \
    f1(x[2],x[3],key->l_key[n],    key->l_key[n + 4]);    \
    f2(x[1],x[2],key->l_key[n + 1],key->l_key[n + 5]);    \
    f3(x[0],x[1],key->l_key[n + 2],key->l_key[n + 6]);    \
    f1(x[3],x[0],key->l_key[n + 3],key->l_key[n + 7])

#define i_rnd(x, n)                             \
    f1(x[3],x[0],key->l_key[n + 3],key->l_key[n + 7]);    \
    f3(x[0],x[1],key->l_key[n + 2],key->l_key[n + 6]);    \
    f2(x[1],x[2],key->l_key[n + 1],key->l_key[n + 5]);    \
    f1(x[2],x[3],key->l_key[n],    key->l_key[n + 4])

#define k_rnd(k,tr,tm)          \
    f1(k[6],k[7],tr[0],tm[0]);  \
    f2(k[5],k[6],tr[1],tm[1]);  \
    f3(k[4],k[5],tr[2],tm[2]);  \
    f1(k[3],k[4],tr[3],tm[3]);  \
    f2(k[2],k[3],tr[4],tm[4]);  \
    f3(k[1],k[2],tr[5],tm[5]);  \
    f1(k[0],k[1],tr[6],tm[6]);  \
    f2(k[7],k[0],tr[7],tm[7])


WIN32DLL_DEFINE
    int _mcrypt_set_key(cast256_key * key, const word32 * in_key,
			const int key_len)
{
	word32 i, j, t, u, cm, cr, lk[8], tm[8], tr[8];


	for (i = 0; i < key_len / sizeof(word32); ++i)
#ifdef WORDS_BIGENDIAN
		lk[i] = byteswap32(in_key[i]);
#else
		lk[i] = in_key[i];
#endif

	for (; i < 8; ++i)

		lk[i] = 0;

	cm = 0x5a827999;
	cr = 19;

	for (i = 0; i < 96; i += 8) {
		for (j = 0; j < 8; ++j) {
			tm[j] = cm;
			cm += 0x6ed9eba1;
			tr[j] = cr;
			cr += 17;
		}

		k_rnd(lk, tr, tm);

		for (j = 0; j < 8; ++j) {
			tm[j] = cm;
			cm += 0x6ed9eba1;
			tr[j] = cr;
			cr += 17;
		}

		k_rnd(lk, tr, tm);

		key->l_key[i + 0] = lk[0];
		key->l_key[i + 1] = lk[2];
		key->l_key[i + 2] = lk[4];
		key->l_key[i + 3] = lk[6];
		key->l_key[i + 4] = lk[7];
		key->l_key[i + 5] = lk[5];
		key->l_key[i + 6] = lk[3];
		key->l_key[i + 7] = lk[1];
	}

	return 0;
}

/* encrypt a block of text  */
/* 16 bytes */
WIN32DLL_DEFINE void _mcrypt_encrypt(cast256_key * key, word32 * blk)
{
	word32 t, u;

#ifdef WORDS_BIGENDIAN
	blk[0] = byteswap32(blk[0]);
	blk[1] = byteswap32(blk[1]);
	blk[2] = byteswap32(blk[2]);
	blk[3] = byteswap32(blk[3]);
#endif

	f_rnd(blk, 0);
	f_rnd(blk, 8);
	f_rnd(blk, 16);
	f_rnd(blk, 24);
	f_rnd(blk, 32);
	f_rnd(blk, 40);
	i_rnd(blk, 48);
	i_rnd(blk, 56);
	i_rnd(blk, 64);
	i_rnd(blk, 72);
	i_rnd(blk, 80);
	i_rnd(blk, 88);

#ifdef WORDS_BIGENDIAN
	blk[0] = byteswap32(blk[0]);
	blk[1] = byteswap32(blk[1]);
	blk[2] = byteswap32(blk[2]);
	blk[3] = byteswap32(blk[3]);
#endif
}

/* decrypt a block of text  */

WIN32DLL_DEFINE void _mcrypt_decrypt(cast256_key * key, word32 * blk)
{
	word32 t, u;

#ifdef WORDS_BIGENDIAN
	blk[0] = byteswap32(blk[0]);
	blk[1] = byteswap32(blk[1]);
	blk[2] = byteswap32(blk[2]);
	blk[3] = byteswap32(blk[3]);
#endif
	f_rnd(blk, 88);
	f_rnd(blk, 80);
	f_rnd(blk, 72);
	f_rnd(blk, 64);
	f_rnd(blk, 56);
	f_rnd(blk, 48);
	i_rnd(blk, 40);
	i_rnd(blk, 32);
	i_rnd(blk, 24);
	i_rnd(blk, 16);
	i_rnd(blk, 8);
	i_rnd(blk, 0);

#ifdef WORDS_BIGENDIAN
	blk[0] = byteswap32(blk[0]);
	blk[1] = byteswap32(blk[1]);
	blk[2] = byteswap32(blk[2]);
	blk[3] = byteswap32(blk[3]);
#endif

}

WIN32DLL_DEFINE int _mcrypt_get_size()
{
	return sizeof(cast256_key);
}

WIN32DLL_DEFINE int _mcrypt_get_block_size()
{
	return 16;
}

WIN32DLL_DEFINE int _is_block_algorithm()
{
	return 1;
}

WIN32DLL_DEFINE int _mcrypt_get_key_size()
{
	return 32;
}

static const int key_sizes[] = { 16, 24, 32 };
WIN32DLL_DEFINE const int *_mcrypt_get_supported_key_sizes(int *len)
{
	*len = sizeof(key_sizes)/sizeof(int);
	return key_sizes;

}

WIN32DLL_DEFINE const char *_mcrypt_get_algorithms_name()
{
return "CAST-256";
}

#define CIPHER "5db4dd765f1d3835615a14afcb5dc2f5"

WIN32DLL_DEFINE int _mcrypt_self_test()
{
	char *keyword;
	unsigned char plaintext[16];
	unsigned char ciphertext[16];
	int blocksize = _mcrypt_get_block_size(), j;
	void *key;
	unsigned char cipher_tmp[200];

	keyword = calloc(1, _mcrypt_get_key_size());
	if (keyword == NULL)
		return -1;

	for (j = 0; j < _mcrypt_get_key_size(); j++) {
		keyword[j] = ((j * 2 + 10) % 256);
	}

	for (j = 0; j < blocksize; j++) {
		plaintext[j] = j % 256;
	}
	key = malloc(_mcrypt_get_size());
	if (key == NULL)
		return -1;

	memcpy(ciphertext, plaintext, blocksize);

	_mcrypt_set_key(key, (void *) keyword, _mcrypt_get_key_size());
	_mcrypt_encrypt(key, (void *) ciphertext);

	free(keyword);

	for (j = 0; j < blocksize; j++) {
		sprintf(&((char *) cipher_tmp)[2 * j], "%.2x",
			ciphertext[j]);
	}

	if (strcmp((char *) cipher_tmp, CIPHER) != 0) {
		printf("failed compatibility\n");
		printf("Expected: %s\nGot: %s\n", CIPHER,
		       (char *) cipher_tmp);
		free(key);
		return -1;
	}
	_mcrypt_decrypt(key, (void *) ciphertext);

	free(key);

	if (strcmp(ciphertext, plaintext) != 0) {
		printf("failed internally\n");
		return -1;
	}

	return 0;
}

WIN32DLL_DEFINE word32 _mcrypt_algorithm_version()
{
	return 20010801;
}

#ifdef WIN32
# ifdef USE_LTDL
WIN32DLL_DEFINE int main (void)
{
       /* empty main function to avoid linker error (see cygwin FAQ) */
}
# endif
#endif
