#include "md5.h"
#include <iomanip>
#include <assert.h>
#include <chrono>

using namespace std;
using namespace chrono;

/**
 * StringProcess: 将单个输入字符串转换成MD5计算所需的消息数组
 * @param input 输入
 * @param[out] n_byte 用于给调用者传递额外的返回值，即最终Byte数组的长度
 * @return Byte消息数组
 */
Byte *StringProcess(string input, int *n_byte)
{
	// 将输入的字符串转换为Byte为单位的数组
	Byte *blocks = (Byte *)input.c_str();
	int length = input.length();

	// 计算原始消息长度（以比特为单位）
	int bitLength = length * 8;

	// paddingBits: 原始消息需要的padding长度（以bit为单位）
	// 对于给定的消息，将其补齐至length%512==448为止
	// 需要注意的是，即便给定的消息满足length%512==448，也需要再pad 512bits
	int paddingBits = bitLength % 512;
	if (paddingBits > 448)
	{
		paddingBits += 512 - (paddingBits - 448);
	}
	else if (paddingBits < 448)
	{
		paddingBits = 448 - paddingBits;
	}
	else if (paddingBits == 448)
	{
		paddingBits = 512;
	}

	// 原始消息需要的padding长度（以Byte为单位）
	int paddingBytes = paddingBits / 8;
	// 创建最终的字节数组
	// length + paddingBytes + 8:
	// 1. length为原始消息的长度（bits）
	// 2. paddingBytes为原始消息需要的padding长度（Bytes）
	// 3. 在pad到length%512==448之后，需要额外附加64bits的原始消息长度，即8个bytes
	int paddedLength = length + paddingBytes + 8;
	Byte *paddedMessage = new Byte[paddedLength];

	// 复制原始消息
	memcpy(paddedMessage, blocks, length);

	// 添加填充字节。填充时，第一位为1，后面的所有位均为0。
	// 所以第一个byte是0x80
	paddedMessage[length] = 0x80;							 // 添加一个0x80字节
	memset(paddedMessage + length + 1, 0, paddingBytes - 1); // 填充0字节

	// 添加消息长度（64比特，小端格式）
	for (int i = 0; i < 8; ++i)
	{
		// 特别注意此处应当将bitLength转换为uint64_t
		// 这里的length是原始消息的长度
		paddedMessage[length + paddingBytes + i] = ((uint64_t)length * 8 >> (i * 8)) & 0xFF;
	}

	// 验证长度是否满足要求。此时长度应当是512bit的倍数
	int residual = 8 * paddedLength % 512;
	// assert(residual == 0);

	// 在填充+添加长度之后，消息被分为n_blocks个512bit的部分
	*n_byte = paddedLength;
	return paddedMessage;
}


/**
 * MD5Hash: 将单个输入字符串转换成MD5
 * @param input 输入
 * @param[out] state 用于给调用者传递额外的返回值，即最终的缓冲区，也就是MD5的结果
 */
void MD5Hash(string input, bit32* state)
{
    Byte* paddedMessage;
    int messageLength;
    paddedMessage = StringProcess(input, &messageLength);
    assert(messageLength % 64 == 0);
    int n_blocks = messageLength / 64;

    state[0] = 0x67452301;
    state[1] = 0xefcdab89;
    state[2] = 0x98badcfe;
    state[3] = 0x10325476;

    for (int i = 0; i < n_blocks; ++i)
    {
        bit32 x[16];
        for (int j = 0; j < 16; ++j)
        {
            x[j] = (paddedMessage[64 * i + j * 4]) |
                   (paddedMessage[64 * i + j * 4 + 1] << 8) |
                   (paddedMessage[64 * i + j * 4 + 2] << 16) |
                   (paddedMessage[64 * i + j * 4 + 3] << 24);
        }

        bit32 a = state[0], b = state[1], c = state[2], d = state[3];

        /* Round 1 */
        FF(a, b, c, d, x[0], s11, 0xd76aa478);
        FF(d, a, b, c, x[1], s12, 0xe8c7b756);
        FF(c, d, a, b, x[2], s13, 0x242070db);
        FF(b, c, d, a, x[3], s14, 0xc1bdceee);
        FF(a, b, c, d, x[4], s11, 0xf57c0faf);
        FF(d, a, b, c, x[5], s12, 0x4787c62a);
        FF(c, d, a, b, x[6], s13, 0xa8304613);
        FF(b, c, d, a, x[7], s14, 0xfd469501);
        FF(a, b, c, d, x[8], s11, 0x698098d8);
        FF(d, a, b, c, x[9], s12, 0x8b44f7af);
        FF(c, d, a, b, x[10], s13, 0xffff5bb1);
        FF(b, c, d, a, x[11], s14, 0x895cd7be);
        FF(a, b, c, d, x[12], s11, 0x6b901122);
        FF(d, a, b, c, x[13], s12, 0xfd987193);
        FF(c, d, a, b, x[14], s13, 0xa679438e);
        FF(b, c, d, a, x[15], s14, 0x49b40821);

        /* Round 2 */
        GG(a, b, c, d, x[1], s21, 0xf61e2562);
        GG(d, a, b, c, x[6], s22, 0xc040b340);
        GG(c, d, a, b, x[11], s23, 0x265e5a51);
        GG(b, c, d, a, x[0], s24, 0xe9b6c7aa);
        GG(a, b, c, d, x[5], s21, 0xd62f105d);
        GG(d, a, b, c, x[10], s22, 0x2441453);
        GG(c, d, a, b, x[15], s23, 0xd8a1e681);
        GG(b, c, d, a, x[4], s24, 0xe7d3fbc8);
        GG(a, b, c, d, x[9], s21, 0x21e1cde6);
        GG(d, a, b, c, x[14], s22, 0xc33707d6);
        GG(c, d, a, b, x[3], s23, 0xf4d50d87);
        GG(b, c, d, a, x[8], s24, 0x455a14ed);
        GG(a, b, c, d, x[13], s21, 0xa9e3e905);
        GG(d, a, b, c, x[2], s22, 0xfcefa3f8);
        GG(c, d, a, b, x[7], s23, 0x676f02d9);
        GG(b, c, d, a, x[12], s24, 0x8d2a4c8a);

        /* Round 3 */
        HH(a, b, c, d, x[5], s31, 0xfffa3942);
        HH(d, a, b, c, x[8], s32, 0x8771f681);
        HH(c, d, a, b, x[11], s33, 0x6d9d6122);
        HH(b, c, d, a, x[14], s34, 0xfde5380c);
        HH(a, b, c, d, x[1], s31, 0xa4beea44);
        HH(d, a, b, c, x[4], s32, 0x4bdecfa9);
        HH(c, d, a, b, x[7], s33, 0xf6bb4b60);
        HH(b, c, d, a, x[10], s34, 0xbebfbc70);
        HH(a, b, c, d, x[13], s31, 0x289b7ec6);
        HH(d, a, b, c, x[0], s32, 0xeaa127fa);
        HH(c, d, a, b, x[3], s33, 0xd4ef3085);
        HH(b, c, d, a, x[6], s34, 0x4881d05);
        HH(a, b, c, d, x[9], s31, 0xd9d4d039);
        HH(d, a, b, c, x[12], s32, 0xe6db99e5);
        HH(c, d, a, b, x[15], s33, 0x1fa27cf8);
        HH(b, c, d, a, x[2], s34, 0xc4ac5665);

        /* Round 4 */
        II(a, b, c, d, x[0], s41, 0xf4292244);
        II(d, a, b, c, x[7], s42, 0x432aff97);
        II(c, d, a, b, x[14], s43, 0xab9423a7);
        II(b, c, d, a, x[5], s44, 0xfc93a039);
        II(a, b, c, d, x[12], s41, 0x655b59c3);
        II(d, a, b, c, x[3], s42, 0x8f0ccc92);
        II(c, d, a, b, x[10], s43, 0xffeff47d);
        II(b, c, d, a, x[1], s44, 0x85845dd1);
        II(a, b, c, d, x[8], s41, 0x6fa87e4f);
        II(d, a, b, c, x[15], s42, 0xfe2ce6e0);
        II(c, d, a, b, x[6], s43, 0xa3014314);
        II(b, c, d, a, x[13], s44, 0x4e0811a1);
        II(a, b, c, d, x[4], s41, 0xf7537e82);
        II(d, a, b, c, x[11], s42, 0xbd3af235);
        II(c, d, a, b, x[2], s43, 0x2ad7d2bb);
        II(b, c, d, a, x[9], s44, 0xeb86d391);

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
    }

    for (int i = 0; i < 4; ++i)
    {
        uint32_t v = state[i];
        state[i] = ((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v & 0xff0000) >> 8) | ((v & 0xff000000) >> 24);
    }

    delete[] paddedMessage;
}

/**
 * MD5HashSIMD: 将四个输入字符串同时并行转换成MD5
 * @param inputs 输入的四个字符串
 * @param[out] states 输出的四个结果
 */
/**
 * MD5HashSIMD: 将四个输入字符串同时并行转换成MD5
 * @param inputs 输入的四个字符串
 * @param[out] states 输出的四个结果
 */
/**
 * MD5HashSIMD: 将四个输入字符串同时并行转换成MD5
 * @param inputs 输入的四个字符串
 * @param[out] states 输出的四个结果
 */
void MD5HashSIMD(string inputs[4], bit32 states[4][4])
{
    Byte* paddedMessages[4];
    int messageLengths[4];

    for (int i = 0; i < 4; ++i)
    {
        paddedMessages[i] = StringProcess(inputs[i], &messageLengths[i]);
        assert(messageLengths[i] == messageLengths[0]);
    }
    int n_blocks = messageLengths[0] / 64;

    uint32x4_t A = vdupq_n_u32(0x67452301);
    uint32x4_t B = vdupq_n_u32(0xefcdab89);
    uint32x4_t C = vdupq_n_u32(0x98badcfe);
    uint32x4_t D = vdupq_n_u32(0x10325476);

    for (int blk = 0; blk < n_blocks; ++blk)
    {
        uint32x4_t X[16];
        for (int i = 0; i < 16; ++i)
        {
            uint32_t words[4];
            for (int j = 0; j < 4; ++j)
            {
                int base = blk * 64 + i * 4;
                words[j] = (paddedMessages[j][base]) |
                           (paddedMessages[j][base + 1] << 8) |
                           (paddedMessages[j][base + 2] << 16) |
                           (paddedMessages[j][base + 3] << 24);
            }
            X[i] = vld1q_u32(words);
        }

        uint32x4_t a = A, b = B, c = C, d = D;

        /* Round 1 */
        FF_SIMD(a, b, c, d, X[0], s11, 0xd76aa478);
        FF_SIMD(d, a, b, c, X[1], s12, 0xe8c7b756);
        FF_SIMD(c, d, a, b, X[2], s13, 0x242070db);
        FF_SIMD(b, c, d, a, X[3], s14, 0xc1bdceee);
        FF_SIMD(a, b, c, d, X[4], s11, 0xf57c0faf);
        FF_SIMD(d, a, b, c, X[5], s12, 0x4787c62a);
        FF_SIMD(c, d, a, b, X[6], s13, 0xa8304613);
        FF_SIMD(b, c, d, a, X[7], s14, 0xfd469501);
        FF_SIMD(a, b, c, d, X[8], s11, 0x698098d8);
        FF_SIMD(d, a, b, c, X[9], s12, 0x8b44f7af);
        FF_SIMD(c, d, a, b, X[10], s13, 0xffff5bb1);
        FF_SIMD(b, c, d, a, X[11], s14, 0x895cd7be);
        FF_SIMD(a, b, c, d, X[12], s11, 0x6b901122);
        FF_SIMD(d, a, b, c, X[13], s12, 0xfd987193);
        FF_SIMD(c, d, a, b, X[14], s13, 0xa679438e);
        FF_SIMD(b, c, d, a, X[15], s14, 0x49b40821);

        /* Round 2 */
        GG_SIMD(a, b, c, d, X[1], s21, 0xf61e2562);
        GG_SIMD(d, a, b, c, X[6], s22, 0xc040b340);
        GG_SIMD(c, d, a, b, X[11], s23, 0x265e5a51);
        GG_SIMD(b, c, d, a, X[0], s24, 0xe9b6c7aa);
        GG_SIMD(a, b, c, d, X[5], s21, 0xd62f105d);
        GG_SIMD(d, a, b, c, X[10], s22, 0x2441453);
        GG_SIMD(c, d, a, b, X[15], s23, 0xd8a1e681);
        GG_SIMD(b, c, d, a, X[4], s24, 0xe7d3fbc8);
        GG_SIMD(a, b, c, d, X[9], s21, 0x21e1cde6);
        GG_SIMD(d, a, b, c, X[14], s22, 0xc33707d6);
        GG_SIMD(c, d, a, b, X[3], s23, 0xf4d50d87);
        GG_SIMD(b, c, d, a, X[8], s24, 0x455a14ed);
        GG_SIMD(a, b, c, d, X[13], s21, 0xa9e3e905);
        GG_SIMD(d, a, b, c, X[2], s22, 0xfcefa3f8);
        GG_SIMD(c, d, a, b, X[7], s23, 0x676f02d9);
        GG_SIMD(b, c, d, a, X[12], s24, 0x8d2a4c8a);

        /* Round 3 */
        HH_SIMD(a, b, c, d, X[5], s31, 0xfffa3942);
        HH_SIMD(d, a, b, c, X[8], s32, 0x8771f681);
        HH_SIMD(c, d, a, b, X[11], s33, 0x6d9d6122);
        HH_SIMD(b, c, d, a, X[14], s34, 0xfde5380c);
        HH_SIMD(a, b, c, d, X[1], s31, 0xa4beea44);
        HH_SIMD(d, a, b, c, X[4], s32, 0x4bdecfa9);
        HH_SIMD(c, d, a, b, X[7], s33, 0xf6bb4b60);
        HH_SIMD(b, c, d, a, X[10], s34, 0xbebfbc70);
        HH_SIMD(a, b, c, d, X[13], s31, 0x289b7ec6);
        HH_SIMD(d, a, b, c, X[0], s32, 0xeaa127fa);
        HH_SIMD(c, d, a, b, X[3], s33, 0xd4ef3085);
        HH_SIMD(b, c, d, a, X[6], s34, 0x4881d05);
        HH_SIMD(a, b, c, d, X[9], s31, 0xd9d4d039);
        HH_SIMD(d, a, b, c, X[12], s32, 0xe6db99e5);
        HH_SIMD(c, d, a, b, X[15], s33, 0x1fa27cf8);
        HH_SIMD(b, c, d, a, X[2], s34, 0xc4ac5665);

        /* Round 4 */
        II_SIMD(a, b, c, d, X[0], s41, 0xf4292244);
        II_SIMD(d, a, b, c, X[7], s42, 0x432aff97);
        II_SIMD(c, d, a, b, X[14], s43, 0xab9423a7);
        II_SIMD(b, c, d, a, X[5], s44, 0xfc93a039);
        II_SIMD(a, b, c, d, X[12], s41, 0x655b59c3);
        II_SIMD(d, a, b, c, X[3], s42, 0x8f0ccc92);
        II_SIMD(c, d, a, b, X[10], s43, 0xffeff47d);
        II_SIMD(b, c, d, a, X[1], s44, 0x85845dd1);
        II_SIMD(a, b, c, d, X[8], s41, 0x6fa87e4f);
        II_SIMD(d, a, b, c, X[15], s42, 0xfe2ce6e0);
        II_SIMD(c, d, a, b, X[6], s43, 0xa3014314);
        II_SIMD(b, c, d, a, X[13], s44, 0x4e0811a1);
        II_SIMD(a, b, c, d, X[4], s41, 0xf7537e82);
        II_SIMD(d, a, b, c, X[11], s42, 0xbd3af235);
        II_SIMD(c, d, a, b, X[2], s43, 0x2ad7d2bb);
        II_SIMD(b, c, d, a, X[9], s44, 0xeb86d391);

        A = vaddq_u32(A, a);
        B = vaddq_u32(B, b);
        C = vaddq_u32(C, c);
        D = vaddq_u32(D, d);
    }

    uint32_t A_out[4], B_out[4], C_out[4], D_out[4];
    vst1q_u32(A_out, A);
    vst1q_u32(B_out, B);
    vst1q_u32(C_out, C);
    vst1q_u32(D_out, D);

    for (int i = 0; i < 4; ++i)
    {
        states[i][0] = ((A_out[i] & 0xff) << 24) | ((A_out[i] & 0xff00) << 8) | ((A_out[i] & 0xff0000) >> 8) | ((A_out[i] & 0xff000000) >> 24);
        states[i][1] = ((B_out[i] & 0xff) << 24) | ((B_out[i] & 0xff00) << 8) | ((B_out[i] & 0xff0000) >> 8) | ((B_out[i] & 0xff000000) >> 24);
        states[i][2] = ((C_out[i] & 0xff) << 24) | ((C_out[i] & 0xff00) << 8) | ((C_out[i] & 0xff0000) >> 8) | ((C_out[i] & 0xff000000) >> 24);
        states[i][3] = ((D_out[i] & 0xff) << 24) | ((D_out[i] & 0xff00) << 8) | ((D_out[i] & 0xff0000) >> 8) | ((D_out[i] & 0xff000000) >> 24);
    }

    for (int i = 0; i < 4; ++i)
    {
        delete[] paddedMessages[i];
    }
}

void MD5HashSIMD2(string inputs[2], bit32 states[2][4]) {
    Byte* paddedMessages[2];
    int messageLengths[2];

    // 为每个输入字符串进行填充和预处理
    for (int i = 0; i < 2; ++i) {
        paddedMessages[i] = StringProcess(inputs[i], &messageLengths[i]);
        assert(messageLengths[i] == messageLengths[0]);
    }
    int n_blocks = messageLengths[0] / 64;

    uint32x4_t A = vdupq_n_u32(0x67452301);
    uint32x4_t B = vdupq_n_u32(0xefcdab89);
    uint32x4_t C = vdupq_n_u32(0x98badcfe);
    uint32x4_t D = vdupq_n_u32(0x10325476);

    // 循环处理每个块
    for (int blk = 0; blk < n_blocks; ++blk) {
        uint32x4_t X[16];
        for (int i = 0; i < 16; ++i) {
            uint32_t words[2];  // 2 路并行
            for (int j = 0; j < 2; ++j) {
                int base = blk * 64 + i * 4;
                words[j] = (paddedMessages[j][base]) |
                           (paddedMessages[j][base + 1] << 8) |
                           (paddedMessages[j][base + 2] << 16) |
                           (paddedMessages[j][base + 3] << 24);
            }
            X[i] = vld1q_u32(words);
        }

        uint32x4_t a = A, b = B, c = C, d = D;

        /* Round 1 */
        FF_SIMD(a, b, c, d, X[0], s11, 0xd76aa478);
        FF_SIMD(d, a, b, c, X[1], s12, 0xe8c7b756);
        FF_SIMD(c, d, a, b, X[2], s13, 0x242070db);
        FF_SIMD(b, c, d, a, X[3], s14, 0xc1bdceee);
        FF_SIMD(a, b, c, d, X[4], s11, 0xf57c0faf);
        FF_SIMD(d, a, b, c, X[5], s12, 0x4787c62a);
        FF_SIMD(c, d, a, b, X[6], s13, 0xa8304613);
        FF_SIMD(b, c, d, a, X[7], s14, 0xfd469501);
        FF_SIMD(a, b, c, d, X[8], s11, 0x698098d8);
        FF_SIMD(d, a, b, c, X[9], s12, 0x8b44f7af);
        FF_SIMD(c, d, a, b, X[10], s13, 0xffff5bb1);
        FF_SIMD(b, c, d, a, X[11], s14, 0x895cd7be);
        FF_SIMD(a, b, c, d, X[12], s11, 0x6b901122);
        FF_SIMD(d, a, b, c, X[13], s12, 0xfd987193);
        FF_SIMD(c, d, a, b, X[14], s13, 0xa679438e);
        FF_SIMD(b, c, d, a, X[15], s14, 0x49b40821);

        /* Round 2 */
        GG_SIMD(a, b, c, d, X[1], s21, 0xf61e2562);
        GG_SIMD(d, a, b, c, X[6], s22, 0xc040b340);
        GG_SIMD(c, d, a, b, X[11], s23, 0x265e5a51);
        GG_SIMD(b, c, d, a, X[0], s24, 0xe9b6c7aa);
        GG_SIMD(a, b, c, d, X[5], s21, 0xd62f105d);
        GG_SIMD(d, a, b, c, X[10], s22, 0x2441453);
        GG_SIMD(c, d, a, b, X[15], s23, 0xd8a1e681);
        GG_SIMD(b, c, d, a, X[4], s24, 0xe7d3fbc8);
        GG_SIMD(a, b, c, d, X[9], s21, 0x21e1cde6);
        GG_SIMD(d, a, b, c, X[14], s22, 0xc33707d6);
        GG_SIMD(c, d, a, b, X[3], s23, 0xf4d50d87);
        GG_SIMD(b, c, d, a, X[8], s24, 0x455a14ed);
        GG_SIMD(a, b, c, d, X[13], s21, 0xa9e3e905);
        GG_SIMD(d, a, b, c, X[2], s22, 0xfcefa3f8);
        GG_SIMD(c, d, a, b, X[7], s23, 0x676f02d9);
        GG_SIMD(b, c, d, a, X[12], s24, 0x8d2a4c8a);

        /* Round 3 */
        HH_SIMD(a, b, c, d, X[5], s31, 0xfffa3942);
        HH_SIMD(d, a, b, c, X[8], s32, 0x8771f681);
        HH_SIMD(c, d, a, b, X[11], s33, 0x6d9d6122);
        HH_SIMD(b, c, d, a, X[14], s34, 0xfde5380c);
        HH_SIMD(a, b, c, d, X[1], s31, 0xa4beea44);
        HH_SIMD(d, a, b, c, X[4], s32, 0x4bdecfa9);
        HH_SIMD(c, d, a, b, X[7], s33, 0xf6bb4b60);
        HH_SIMD(b, c, d, a, X[10], s34, 0xbebfbc70);
        HH_SIMD(a, b, c, d, X[13], s31, 0x289b7ec6);
        HH_SIMD(d, a, b, c, X[0], s32, 0xeaa127fa);
        HH_SIMD(c, d, a, b, X[3], s33, 0xd4ef3085);
        HH_SIMD(b, c, d, a, X[6], s34, 0x4881d05);
        HH_SIMD(a, b, c, d, X[9], s31, 0xd9d4d039);
        HH_SIMD(d, a, b, c, X[12], s32, 0xe6db99e5);
        HH_SIMD(c, d, a, b, X[15], s33, 0x1fa27cf8);
        HH_SIMD(b, c, d, a, X[2], s34, 0xc4ac5665);

        /* Round 4 */
        II_SIMD(a, b, c, d, X[0], s41, 0xf4292244);
        II_SIMD(d, a, b, c, X[7], s42, 0x432aff97);
        II_SIMD(c, d, a, b, X[14], s43, 0xab9423a7);
        II_SIMD(b, c, d, a, X[5], s44, 0xfc93a039);
        II_SIMD(a, b, c, d, X[12], s41, 0x655b59c3);
        II_SIMD(d, a, b, c, X[3], s42, 0x8f0ccc92);
        II_SIMD(c, d, a, b, X[10], s43, 0xffeff47d);
        II_SIMD(b, c, d, a, X[1], s44, 0x85845dd1);
        II_SIMD(a, b, c, d, X[8], s41, 0x6fa87e4f);
        II_SIMD(d, a, b, c, X[15], s42, 0xfe2ce6e0);
        II_SIMD(c, d, a, b, X[6], s43, 0xa3014314);
        II_SIMD(b, c, d, a, X[13], s44, 0x4e0811a1);
        II_SIMD(a, b, c, d, X[4], s41, 0xf7537e82);
        II_SIMD(d, a, b, c, X[11], s42, 0xbd3af235);
        II_SIMD(c, d, a, b, X[2], s43, 0x2ad7d2bb);
        II_SIMD(b, c, d, a, X[9], s44, 0xeb86d391);

        A = vaddq_u32(A, a);
        B = vaddq_u32(B, b);
        C = vaddq_u32(C, c);
        D = vaddq_u32(D, d);
    }

    uint32_t A_out[4], B_out[4], C_out[4], D_out[4];
    vst1q_u32(A_out, A);
    vst1q_u32(B_out, B);
    vst1q_u32(C_out, C);
    vst1q_u32(D_out, D);

    for (int i = 0; i < 2; ++i) {
        states[i][0] = ((A_out[i] & 0xff) << 24) | ((A_out[i] & 0xff00) << 8) | ((A_out[i] & 0xff0000) >> 8) | ((A_out[i] & 0xff000000) >> 24);
        states[i][1] = ((B_out[i] & 0xff) << 24) | ((B_out[i] & 0xff00) << 8) | ((B_out[i] & 0xff0000) >> 8) | ((B_out[i] & 0xff000000) >> 24);
        states[i][2] = ((C_out[i] & 0xff) << 24) | ((C_out[i] & 0xff00) << 8) | ((C_out[i] & 0xff0000) >> 8) | ((C_out[i] & 0xff000000) >> 24);
        states[i][3] = ((D_out[i] & 0xff) << 24) | ((D_out[i] & 0xff00) << 8) | ((D_out[i] & 0xff0000) >> 8) | ((D_out[i] & 0xff000000) >> 24);
    }

    // 释放内存
    for (int i = 0; i < 2; ++i) {
        delete[] paddedMessages[i];
    }
}


void MD5HashSIMD8(string inputs[8], bit32 states[8][4]) {
    Byte* paddedMessages[8];
    int messageLengths[8];

    // 为每个输入字符串进行填充和预处理
    for (int i = 0; i < 8; ++i) {
        paddedMessages[i] = StringProcess(inputs[i], &messageLengths[i]);
        assert(messageLengths[i] == messageLengths[0]);
    }
    int n_blocks = messageLengths[0] / 64;

    uint32x4_t A = vdupq_n_u32(0x67452301);
    uint32x4_t B = vdupq_n_u32(0xefcdab89);
    uint32x4_t C = vdupq_n_u32(0x98badcfe);
    uint32x4_t D = vdupq_n_u32(0x10325476);

    // 循环处理每个块
    for (int blk = 0; blk < n_blocks; ++blk) {
        uint32x4_t X[16];
        for (int i = 0; i < 16; ++i) {
            uint32_t words[8];  // 8 路并行
            for (int j = 0; j < 8; ++j) {
                int base = blk * 64 + i * 4;
                words[j] = (paddedMessages[j][base]) |
                           (paddedMessages[j][base + 1] << 8) |
                           (paddedMessages[j][base + 2] << 16) |
                           (paddedMessages[j][base + 3] << 24);
            }
            X[i] = vld1q_u32(words);
        }

        uint32x4_t a = A, b = B, c = C, d = D;

        /* Round 1 */
        FF_SIMD(a, b, c, d, X[0], s11, 0xd76aa478);
        FF_SIMD(d, a, b, c, X[1], s12, 0xe8c7b756);
        FF_SIMD(c, d, a, b, X[2], s13, 0x242070db);
        FF_SIMD(b, c, d, a, X[3], s14, 0xc1bdceee);
        FF_SIMD(a, b, c, d, X[4], s11, 0xf57c0faf);
        FF_SIMD(d, a, b, c, X[5], s12, 0x4787c62a);
        FF_SIMD(c, d, a, b, X[6], s13, 0xa8304613);
        FF_SIMD(b, c, d, a, X[7], s14, 0xfd469501);
        FF_SIMD(a, b, c, d, X[8], s11, 0x698098d8);
        FF_SIMD(d, a, b, c, X[9], s12, 0x8b44f7af);
        FF_SIMD(c, d, a, b, X[10], s13, 0xffff5bb1);
        FF_SIMD(b, c, d, a, X[11], s14, 0x895cd7be);
        FF_SIMD(a, b, c, d, X[12], s11, 0x6b901122);
        FF_SIMD(d, a, b, c, X[13], s12, 0xfd987193);
        FF_SIMD(c, d, a, b, X[14], s13, 0xa679438e);
        FF_SIMD(b, c, d, a, X[15], s14, 0x49b40821);

        /* Round 2 */
        GG_SIMD(a, b, c, d, X[1], s21, 0xf61e2562);
        GG_SIMD(d, a, b, c, X[6], s22, 0xc040b340);
        GG_SIMD(c, d, a, b, X[11], s23, 0x265e5a51);
        GG_SIMD(b, c, d, a, X[0], s24, 0xe9b6c7aa);
        GG_SIMD(a, b, c, d, X[5], s21, 0xd62f105d);
        GG_SIMD(d, a, b, c, X[10], s22, 0x2441453);
        GG_SIMD(c, d, a, b, X[15], s23, 0xd8a1e681);
        GG_SIMD(b, c, d, a, X[4], s24, 0xe7d3fbc8);
        GG_SIMD(a, b, c, d, X[9], s21, 0x21e1cde6);
        GG_SIMD(d, a, b, c, X[14], s22, 0xc33707d6);
        GG_SIMD(c, d, a, b, X[3], s23, 0xf4d50d87);
        GG_SIMD(b, c, d, a, X[8], s24, 0x455a14ed);
        GG_SIMD(a, b, c, d, X[13], s21, 0xa9e3e905);
        GG_SIMD(d, a, b, c, X[2], s22, 0xfcefa3f8);
        GG_SIMD(c, d, a, b, X[7], s23, 0x676f02d9);
        GG_SIMD(b, c, d, a, X[12], s24, 0x8d2a4c8a);

        /* Round 3 */
        HH_SIMD(a, b, c, d, X[5], s31, 0xfffa3942);
        HH_SIMD(d, a, b, c, X[8], s32, 0x8771f681);
        HH_SIMD(c, d, a, b, X[11], s33, 0x6d9d6122);
        HH_SIMD(b, c, d, a, X[14], s34, 0xfde5380c);
        HH_SIMD(a, b, c, d, X[1], s31, 0xa4beea44);
        HH_SIMD(d, a, b, c, X[4], s32, 0x4bdecfa9);
        HH_SIMD(c, d, a, b, X[7], s33, 0xf6bb4b60);
        HH_SIMD(b, c, d, a, X[10], s34, 0xbebfbc70);
        HH_SIMD(a, b, c, d, X[13], s31, 0x289b7ec6);
        HH_SIMD(d, a, b, c, X[0], s32, 0xeaa127fa);
        HH_SIMD(c, d, a, b, X[3], s33, 0xd4ef3085);
        HH_SIMD(b, c, d, a, X[6], s34, 0x4881d05);
        HH_SIMD(a, b, c, d, X[9], s31, 0xd9d4d039);
        HH_SIMD(d, a, b, c, X[12], s32, 0xe6db99e5);
        HH_SIMD(c, d, a, b, X[15], s33, 0x1fa27cf8);
        HH_SIMD(b, c, d, a, X[2], s34, 0xc4ac5665);

        /* Round 4 */
        II_SIMD(a, b, c, d, X[0], s41, 0xf4292244);
        II_SIMD(d, a, b, c, X[7], s42, 0x432aff97);
        II_SIMD(c, d, a, b, X[14], s43, 0xab9423a7);
        II_SIMD(b, c, d, a, X[5], s44, 0xfc93a039);
        II_SIMD(a, b, c, d, X[12], s41, 0x655b59c3);
        II_SIMD(d, a, b, c, X[3], s42, 0x8f0ccc92);
        II_SIMD(c, d, a, b, X[10], s43, 0xffeff47d);
        II_SIMD(b, c, d, a, X[1], s44, 0x85845dd1);
        II_SIMD(a, b, c, d, X[8], s41, 0x6fa87e4f);
        II_SIMD(d, a, b, c, X[15], s42, 0xfe2ce6e0);
        II_SIMD(c, d, a, b, X[6], s43, 0xa3014314);
        II_SIMD(b, c, d, a, X[13], s44, 0x4e0811a1);
        II_SIMD(a, b, c, d, X[4], s41, 0xf7537e82);
        II_SIMD(d, a, b, c, X[11], s42, 0xbd3af235);
        II_SIMD(c, d, a, b, X[2], s43, 0x2ad7d2bb);
        II_SIMD(b, c, d, a, X[9], s44, 0xeb86d391);

        A = vaddq_u32(A, a);
        B = vaddq_u32(B, b);
        C = vaddq_u32(C, c);
        D = vaddq_u32(D, d);
    }

    uint32_t A_out[8], B_out[8], C_out[8], D_out[8];
    vst1q_u32(A_out, A);
    vst1q_u32(B_out, B);
    vst1q_u32(C_out, C);
    vst1q_u32(D_out, D);

    for (int i = 0; i < 8; ++i) {
        states[i][0] = ((A_out[i] & 0xff) << 24) | ((A_out[i] & 0xff00) << 8) | ((A_out[i] & 0xff0000) >> 8) | ((A_out[i] & 0xff000000) >> 24);
        states[i][1] = ((B_out[i] & 0xff) << 24) | ((B_out[i] & 0xff00) << 8) | ((B_out[i] & 0xff0000) >> 8) | ((B_out[i] & 0xff000000) >> 24);
        states[i][2] = ((C_out[i] & 0xff) << 24) | ((C_out[i] & 0xff00) << 8) | ((C_out[i] & 0xff0000) >> 8) | ((C_out[i] & 0xff000000) >> 24);
        states[i][3] = ((D_out[i] & 0xff) << 24) | ((D_out[i] & 0xff00) << 8) | ((D_out[i] & 0xff0000) >> 8) | ((D_out[i] & 0xff000000) >> 24);
    }

    // 释放内存
    for (int i = 0; i < 8; ++i) {
        delete[] paddedMessages[i];
    }
}


void MD5HashSIMD16(string inputs[16], bit32 states[16][4]) {
    Byte* paddedMessages[16];
    int messageLengths[16];

    // 为每个输入字符串进行填充和预处理
    for (int i = 0; i < 16; ++i) {
        paddedMessages[i] = StringProcess(inputs[i], &messageLengths[i]);
        assert(messageLengths[i] == messageLengths[0]);
    }
    int n_blocks = messageLengths[0] / 64;

    uint32x4_t A = vdupq_n_u32(0x67452301);
    uint32x4_t B = vdupq_n_u32(0xefcdab89);
    uint32x4_t C = vdupq_n_u32(0x98badcfe);
    uint32x4_t D = vdupq_n_u32(0x10325476);

    // 循环处理每个块
    for (int blk = 0; blk < n_blocks; ++blk) {
        uint32x4_t X[16];
        for (int i = 0; i < 16; ++i) {
            uint32_t words[16];  // 16 路并行
            for (int j = 0; j < 16; ++j) {
                int base = blk * 64 + i * 4;
                words[j] = (paddedMessages[j][base]) |
                           (paddedMessages[j][base + 1] << 8) |
                           (paddedMessages[j][base + 2] << 16) |
                           (paddedMessages[j][base + 3] << 24);
            }
            X[i] = vld1q_u32(words);
        }

        uint32x4_t a = A, b = B, c = C, d = D;

        /* Round 1 */
        FF_SIMD(a, b, c, d, X[0], s11, 0xd76aa478);
        FF_SIMD(d, a, b, c, X[1], s12, 0xe8c7b756);
        FF_SIMD(c, d, a, b, X[2], s13, 0x242070db);
        FF_SIMD(b, c, d, a, X[3], s14, 0xc1bdceee);
        FF_SIMD(a, b, c, d, X[4], s11, 0xf57c0faf);
        FF_SIMD(d, a, b, c, X[5], s12, 0x4787c62a);
        FF_SIMD(c, d, a, b, X[6], s13, 0xa8304613);
        FF_SIMD(b, c, d, a, X[7], s14, 0xfd469501);
        FF_SIMD(a, b, c, d, X[8], s11, 0x698098d8);
        FF_SIMD(d, a, b, c, X[9], s12, 0x8b44f7af);
        FF_SIMD(c, d, a, b, X[10], s13, 0xffff5bb1);
        FF_SIMD(b, c, d, a, X[11], s14, 0x895cd7be);
        FF_SIMD(a, b, c, d, X[12], s11, 0x6b901122);
        FF_SIMD(d, a, b, c, X[13], s12, 0xfd987193);
        FF_SIMD(c, d, a, b, X[14], s13, 0xa679438e);
        FF_SIMD(b, c, d, a, X[15], s14, 0x49b40821);

        /* Round 2 */
        GG_SIMD(a, b, c, d, X[1], s21, 0xf61e2562);
        GG_SIMD(d, a, b, c, X[6], s22, 0xc040b340);
        GG_SIMD(c, d, a, b, X[11], s23, 0x265e5a51);
        GG_SIMD(b, c, d, a, X[0], s24, 0xe9b6c7aa);
        GG_SIMD(a, b, c, d, X[5], s21, 0xd62f105d);
        GG_SIMD(d, a, b, c, X[10], s22, 0x2441453);
        GG_SIMD(c, d, a, b, X[15], s23, 0xd8a1e681);
        GG_SIMD(b, c, d, a, X[4], s24, 0xe7d3fbc8);
        GG_SIMD(a, b, c, d, X[9], s21, 0x21e1cde6);
        GG_SIMD(d, a, b, c, X[14], s22, 0xc33707d6);
        GG_SIMD(c, d, a, b, X[3], s23, 0xf4d50d87);
        GG_SIMD(b, c, d, a, X[8], s24, 0x455a14ed);
        GG_SIMD(a, b, c, d, X[13], s21, 0xa9e3e905);
        GG_SIMD(d, a, b, c, X[2], s22, 0xfcefa3f8);
        GG_SIMD(c, d, a, b, X[7], s23, 0x676f02d9);
        GG_SIMD(b, c, d, a, X[12], s24, 0x8d2a4c8a);

        /* Round 3 */
        HH_SIMD(a, b, c, d, X[5], s31, 0xfffa3942);
        HH_SIMD(d, a, b, c, X[8], s32, 0x8771f681);
        HH_SIMD(c, d, a, b, X[11], s33, 0x6d9d6122);
        HH_SIMD(b, c, d, a, X[14], s34, 0xfde5380c);
        HH_SIMD(a, b, c, d, X[1], s31, 0xa4beea44);
        HH_SIMD(d, a, b, c, X[4], s32, 0x4bdecfa9);
        HH_SIMD(c, d, a, b, X[7], s33, 0xf6bb4b60);
        HH_SIMD(b, c, d, a, X[10], s34, 0xbebfbc70);
        HH_SIMD(a, b, c, d, X[13], s31, 0x289b7ec6);
        HH_SIMD(d, a, b, c, X[0], s32, 0xeaa127fa);
        HH_SIMD(c, d, a, b, X[3], s33, 0xd4ef3085);
        HH_SIMD(b, c, d, a, X[6], s34, 0x4881d05);
        HH_SIMD(a, b, c, d, X[9], s31, 0xd9d4d039);
        HH_SIMD(d, a, b, c, X[12], s32, 0xe6db99e5);
        HH_SIMD(c, d, a, b, X[15], s33, 0x1fa27cf8);
        HH_SIMD(b, c, d, a, X[2], s34, 0xc4ac5665);

        /* Round 4 */
        II_SIMD(a, b, c, d, X[0], s41, 0xf4292244);
        II_SIMD(d, a, b, c, X[7], s42, 0x432aff97);
        II_SIMD(c, d, a, b, X[14], s43, 0xab9423a7);
        II_SIMD(b, c, d, a, X[5], s44, 0xfc93a039);
        II_SIMD(a, b, c, d, X[12], s41, 0x655b59c3);
        II_SIMD(d, a, b, c, X[3], s42, 0x8f0ccc92);
        II_SIMD(c, d, a, b, X[10], s43, 0xffeff47d);
        II_SIMD(b, c, d, a, X[1], s44, 0x85845dd1);
        II_SIMD(a, b, c, d, X[8], s41, 0x6fa87e4f);
        II_SIMD(d, a, b, c, X[15], s42, 0xfe2ce6e0);
        II_SIMD(c, d, a, b, X[6], s43, 0xa3014314);
        II_SIMD(b, c, d, a, X[13], s44, 0x4e0811a1);
        II_SIMD(a, b, c, d, X[4], s41, 0xf7537e82);
        II_SIMD(d, a, b, c, X[11], s42, 0xbd3af235);
        II_SIMD(c, d, a, b, X[2], s43, 0x2ad7d2bb);
        II_SIMD(b, c, d, a, X[9], s44, 0xeb86d391);


        A = vaddq_u32(A, a);
        B = vaddq_u32(B, b);
        C = vaddq_u32(C, c);
        D = vaddq_u32(D, d);
    }

    uint32_t A_out[16], B_out[16], C_out[16], D_out[16];
    vst1q_u32(A_out, A);
    vst1q_u32(B_out, B);
    vst1q_u32(C_out, C);
    vst1q_u32(D_out, D);

    for (int i = 0; i < 16; ++i) {
        states[i][0] = ((A_out[i] & 0xff) << 24) | ((A_out[i] & 0xff00) << 8) | ((A_out[i] & 0xff0000) >> 8) | ((A_out[i] & 0xff000000) >> 24);
        states[i][1] = ((B_out[i] & 0xff) << 24) | ((B_out[i] & 0xff00) << 8) | ((B_out[i] & 0xff0000) >> 8) | ((B_out[i] & 0xff000000) >> 24);
        states[i][2] = ((C_out[i] & 0xff) << 24) | ((C_out[i] & 0xff00) << 8) | ((C_out[i] & 0xff0000) >> 8) | ((C_out[i] & 0xff000000) >> 24);
        states[i][3] = ((D_out[i] & 0xff) << 24) | ((D_out[i] & 0xff00) << 8) | ((D_out[i] & 0xff0000) >> 8) | ((D_out[i] & 0xff000000) >> 24);
    }

    // 释放内存
    for (int i = 0; i < 16; ++i) {
        delete[] paddedMessages[i];
    }
}
