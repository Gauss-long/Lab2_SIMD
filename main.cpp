#include "PCFG.h"
#include <chrono>
#include <fstream>
#include "md5.h"
#include <iomanip>
using namespace std;
using namespace chrono;

// 编译指令如下
// g++ main.cpp train.cpp guessing.cpp md5.cpp -o test.exe
// g++ main.cpp train.cpp guessing.cpp md5.cpp -o test.exe -O1
// g++ main.cpp train.cpp guessing.cpp md5.cpp -o test.exe -O2
// bash test.sh 1 1 

// g++ main.cpp train.cpp guessing.cpp md5.cpp -o main
// g++ main.cpp train.cpp guessing.cpp md5.cpp -o main -O1
// g++ main.cpp train.cpp guessing.cpp md5.cpp -o main -O2

int main()
{
    double time_hash = 0;  // 用于MD5哈希的时间
    double time_guess = 0; // 哈希和猜测的总时长
    double time_train = 0; // 模型训练的总时长
    PriorityQueue q;

    // 训练阶段计时
    auto start_train = system_clock::now();
    q.m.train("/guessdata/Rockyou-singleLined-full.txt");
    q.m.order();
    auto end_train = system_clock::now();
    auto duration_train = duration_cast<microseconds>(end_train - start_train);
    time_train = double(duration_train.count()) * microseconds::period::num / microseconds::period::den;

    // 初始化队列
    q.init();
    cout << "here" << endl;
    int curr_num = 0;
    auto start = system_clock::now();
    // 由于需要定期清空内存，我们在这里记录已生成的猜测总数
    int history = 0;

    while (!q.priority.empty())
    {
        q.PopNext();
        q.total_guesses = q.guesses.size();
        
        // 输出生成的口令数量
        if (q.total_guesses - curr_num >= 100000)
        {
            cout << "Guesses generated: " << history + q.total_guesses << endl;
            curr_num = q.total_guesses;

            // 更改实验生成的猜测上限
            int generate_n = 10000000;
            if (history + q.total_guesses > 10000000)
            {
                auto end = system_clock::now();
                auto duration = duration_cast<microseconds>(end - start);
                time_guess = double(duration.count()) * microseconds::period::num / microseconds::period::den;
                cout << "Guess time:" << time_guess - time_hash << " seconds" << endl;
                cout << "Hash time:" << time_hash << " seconds" << endl;
                cout << "Train time:" << time_train << " seconds" << endl;
                break;
            }
        }

        // 对生成的口令进行哈希处理
        if (curr_num > 1000000)
        {
            auto start_hash = system_clock::now();
            /* bit32 state[4];
            for (string pw : q.guesses)
            {
                // 使用SIMD优化的MD5哈希函数
                MD5Hash(pw, state); // 替换为SIMD版本
            } */


            int size = q.guesses.size();
            int i = 0;
            for (; i + 15 < size; i += 16)
            {
                string pws[16] = {
                    q.guesses[i],
                    q.guesses[i + 1],
                    q.guesses[i + 2],
                    q.guesses[i + 3],
                    q.guesses[i + 4],
                    q.guesses[i + 5],
                    q.guesses[i + 6],
                    q.guesses[i + 7],
                    q.guesses[i + 8],
                    q.guesses[i + 9],
                    q.guesses[i + 10],
                    q.guesses[i + 11],
                    q.guesses[i + 12],
                    q.guesses[i + 13],
                    q.guesses[i + 14],
                    q.guesses[i + 15]
                };
                bit32 states[16][4];
                MD5HashSIMD16(pws, states);
            }
            for (; i < size; i++)
            {
                bit32 state[4];
                MD5Hash(q.guesses[i], state);
            }
             
 
            // 哈希所需的总时长计算
            auto end_hash = system_clock::now();
            auto duration = duration_cast<microseconds>(end_hash - start_hash);
            time_hash += double(duration.count()) * microseconds::period::num / microseconds::period::den;

            // 记录已经生成的口令总数
            history += curr_num;
            curr_num = 0;
            q.guesses.clear();
        }
    }


    return 0;
}
