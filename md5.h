#include <iostream>
#include <string>
#include <cstring>
#include <arm_neon.h>

using namespace std;

// 定义了Byte，便于使用
typedef unsigned char Byte;
// 定义了32比特
typedef unsigned int bit32;

// MD5的一系列参数。参数是固定的，其实你不需要看懂这些
#define s11 7
#define s12 12
#define s13 17
#define s14 22
#define s21 5
#define s22 9
#define s23 14
#define s24 20
#define s31 4
#define s32 11
#define s33 16
#define s34 23
#define s41 6
#define s42 10
#define s43 15
#define s44 21

// 基本MD5 functions
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

// 左循环
#define ROTATELEFT(num, n) (((num) << (n)) | ((num) >> (32-(n))))

// 轮函数
#define FF(a, b, c, d, x, s, ac) { \
  (a) += F ((b), (c), (d)) + (x) + ac; \
  (a) = ROTATELEFT ((a), (s)); \
  (a) += (b); \
}
#define GG(a, b, c, d, x, s, ac) { \
  (a) += G ((b), (c), (d)) + (x) + ac; \
  (a) = ROTATELEFT ((a), (s)); \
  (a) += (b); \
}
#define HH(a, b, c, d, x, s, ac) { \
  (a) += H ((b), (c), (d)) + (x) + ac; \
  (a) = ROTATELEFT ((a), (s)); \
  (a) += (b); \
}
#define II(a, b, c, d, x, s, ac) { \
  (a) += I ((b), (c), (d)) + (x) + ac; \
  (a) = ROTATELEFT ((a), (s)); \
  (a) += (b); \
}

// SIMD版基本函数
#define F_SIMD(x, y, z) vorrq_u32(vandq_u32(x, y), vandq_u32(vmvnq_u32(x), z))
#define G_SIMD(x, y, z) vorrq_u32(vandq_u32(x, z), vandq_u32(y, vmvnq_u32(z)))
#define H_SIMD(x, y, z) veorq_u32(veorq_u32(x, y), z)
#define I_SIMD(x, y, z) veorq_u32(y, vorrq_u32(x, vmvnq_u32(z)))

// 左循环 SIMD
inline uint32x4_t ROTATELEFT_SIMD(uint32x4_t num, int n) {
  uint32x4_t left = vshlq_n_u32(num, n);            // 左移
  uint32x4_t right = vshrq_n_u32(num, 32 - n);      // 右移
  return vorrq_u32(left, right);                     // 合并左右移的结果
}


// 四个轮函数 SIMD版
#define FF_SIMD(a, b, c, d, x, s, ac) { \
    a = vaddq_u32(a, vaddq_u32(vaddq_u32(F_SIMD(b, c, d), x), vdupq_n_u32(ac))); \
    a = ROTATELEFT_SIMD(a, s); \
    a = vaddq_u32(a, b); \
}
#define GG_SIMD(a, b, c, d, x, s, ac) { \
    a = vaddq_u32(a, vaddq_u32(vaddq_u32(G_SIMD(b, c, d), x), vdupq_n_u32(ac))); \
    a = ROTATELEFT_SIMD(a, s); \
    a = vaddq_u32(a, b); \
}
#define HH_SIMD(a, b, c, d, x, s, ac) { \
    a = vaddq_u32(a, vaddq_u32(vaddq_u32(H_SIMD(b, c, d), x), vdupq_n_u32(ac))); \
    a = ROTATELEFT_SIMD(a, s); \
    a = vaddq_u32(a, b); \
}
#define II_SIMD(a, b, c, d, x, s, ac) { \
    a = vaddq_u32(a, vaddq_u32(vaddq_u32(I_SIMD(b, c, d), x), vdupq_n_u32(ac))); \
    a = ROTATELEFT_SIMD(a, s); \
    a = vaddq_u32(a, b); \
}

void MD5Hash(string input, bit32 *state);
void MD5HashSIMD(string inputs[4], bit32 states[4][4]);

void MD5HashSIMD2(string inputs[2], bit32 states[2][4]);
void MD5HashSIMD8(string inputs[8], bit32 states[8][4]);
void MD5HashSIMD16(string inputs[16], bit32 states[16][4]);
