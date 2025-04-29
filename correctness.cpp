#include "PCFG.h"
#include "md5.h"
#include <iomanip>
#include <iostream>
#include <string>

using namespace std;
// 编译指令如下：
// g++ correctness.cpp train.cpp guessing.cpp md5.cpp -o test.exe
//执行
// ./test.exe
int main()
{
    string s[4] = {
        "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123",
        "hello world!hello world!hello world!hello world!hello world!hello world!",
        "bvaisdbjasdkafkasdfnavkjnakdjfejfanjsdnfkajdfkajdfjkwanfdjaknsvjkanbjbjadfajwefajksdfakdnsvjadfasjdvabvaisdbjasdkaf",
        "SIMD test stringSIMD test stringSIMD test stringSIMD test stringSIMD"
    };
    cout<<"MD5 Hashing Test" << endl;
    // 分别计算 4 个字符串的 MD5（标量方式）
    bit32 states_scalar[4][4];
    for (int i = 0; i < 4; ++i) {
        MD5Hash(s[i], states_scalar[i]);
        for (int j = 0; j < 4; ++j) {
            cout << std::setw(8) << std::setfill('0') << hex << states_scalar[i][j];
        }
        cout << endl;
    }

    cout<<"MD5_SIMD Hashing Test" << endl;
    // 使用 SIMD 一次性计算 4 个字符串的 MD5
    bit32 states_simd[4][4];
    MD5HashSIMD(s, states_simd);
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            cout << std::setw(8) << std::setfill('0') << hex << states_simd[i][j];
        }
        cout << endl;
    }
}