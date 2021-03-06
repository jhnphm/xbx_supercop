#define KUM_FP_2e128mc_G_BASE const unsigned char base[16*3] = { \
    0xC0, 0x67, 0x91, 0xB8, 0xAC, 0x64, 0x45, 0x7C, 0x44, 0xE2, 0xE2, 0x62, 0x31, 0x79, 0xCE, 0xD9, \
    0xC0, 0x67, 0x91, 0xB8, 0xAC, 0x64, 0x45, 0x7C, 0x44, 0xE2, 0xE2, 0x62, 0x31, 0x79, 0xCE, 0xD9, \
    0xC0, 0x67, 0x91, 0xB8, 0xAC, 0x64, 0x45, 0x7C, 0x44, 0xE2, 0xE2, 0x62, 0x31, 0x79, 0xCE, 0xD9 \
}
/* (X : Y : Z : T) with T = 1. */

#define KUM_FP_2e128mc_G_CNST unsigned char cn[16*1+16*3+16*4+16*3+32*1] = { \
    0xED, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	\
	0x45, 0x60, 0xE8, 0x39, 0xF1, 0xBB, 0xD7, 0x75, 0xAB, 0xC4, 0x5A, 0x23, 0x91, 0x17, 0x3F, 0x55, \
    0x30, 0x24, 0x12, 0xFA, 0xF1, 0x3E, 0x28, 0x85, 0xD7, 0x14, 0xBF, 0xF9, 0x8D, 0xC3, 0x49, 0xD7, \
    0xF0, 0x05, 0xEE, 0xB9, 0x72, 0xE6, 0xEA, 0x96, 0x71, 0x0A, 0x2A, 0xAF, 0xAD, 0x47, 0xA9, 0x48, \
    \
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x58, 0xF3, 0xAE, 0x07, 0x94, 0x06, 0xE8, 0x3E, 0x2C, 0xAB, 0x78, 0x2C, 0x81, 0xC8, 0x61, 0x8B, \
    0x28, 0x23, 0x25, 0xC1, 0x84, 0x06, 0x17, 0x06, 0x2C, 0x11, 0x56, 0x98, 0x79, 0x0A, 0x7A, 0xAD, \
    0xE2, 0x74, 0x93, 0xC3, 0x24, 0x5C, 0x2C, 0xD4, 0xD4, 0x14, 0x12, 0x50, 0xC8, 0x74, 0xC9, 0xFB, \
    \
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    0xC0, 0x67, 0x91, 0xB8, 0xAC, 0x64, 0x45, 0x7C, 0x44, 0xE2, 0xE2, 0x62, 0x31, 0x79, 0xCE, 0xD9, \
    \
    0xF9, 0x3F, 0xA4, 0x6F, 0xAA, 0x88, 0x78, 0x8C, 0x87, 0x39, 0x00, 0xAF, 0x6F, 0xD0, 0x00, 0x4F, 0x15, 0x6F, 0x67, 0x02, 0xD2, 0xFB, 0x0F, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 \
}
/**
 * c for the prime 2^128-c,
 * yd, zd, td,
 * x0, y0, z0, t0,
 * yb, zb, tb, (yb=1 and zb=1 is NOT hardcoded!)
 * r.
 **/
