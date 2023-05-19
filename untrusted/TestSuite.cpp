#include "T3E-Untrusted.h"
#include "OpenSSLHelper.h"

#include <algorithm>
#include <chrono>
#include <cpuid.h>
#include <cstdint>
#include <gtest/gtest.h>
#include <list>
#include <numeric>
#include <string_view>
#include <thread>
#include <tss2/tss2_esys.h>
#include <unordered_map>

#include <openssl/ts.h>

namespace
{
    bool simpleDelay {false};
}

extern "C"
{
    extern TSS2_RC __real_Esys_GetTime(ESYS_CONTEXT* esysContext, ESYS_TR privacyAdminHandle, ESYS_TR signHandle,
                                       ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3,
                                       const TPM2B_DATA* qualifyingData, const TPMT_SIG_SCHEME* inScheme,
                                       TPM2B_ATTEST** timeInfo, TPMT_SIGNATURE** signature);

    TSS2_RC __wrap_Esys_GetTime(ESYS_CONTEXT* esysContext, ESYS_TR privacyAdminHandle, ESYS_TR signHandle,
                                ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, const TPM2B_DATA* qualifyingData,
                                const TPMT_SIG_SCHEME* inScheme, TPM2B_ATTEST** timeInfo, TPMT_SIGNATURE** signature)
    {
        using namespace std::chrono_literals;
        if (simpleDelay)
            std::this_thread::sleep_for(0.5s);

        return __real_Esys_GetTime(esysContext, privacyAdminHandle, signHandle, shandle1, shandle2, shandle3,
                                   qualifyingData, inScheme, timeInfo, signature);
    }

    void t3e_Test_PrintOut(char const* str, size_t len)
    {
        std::cout.write(str, len);
        std::cout << std::endl;
    }

    uint64_t t3e_Test_rdtsc_ocall()
    {
        return __rdtsc();
    }

    int64_t t3e_Test_time_ocall()
    {
        auto currTime = std::chrono::system_clock::now();
        return std::chrono::system_clock::to_time_t(currTime);
    }
}

constexpr auto scheme = t3e::TrustedTimeHandler::ECDSA;

TEST(TrustedTimeTest, BasicStartStop)
{
    using namespace std::chrono_literals;
    t3e::sgx::EnclaveHandler enclave(ENCLAVE_FILE);
    t3e::TrustedTimeHandler timeHandler(enclave, scheme);
    timeHandler.start();

    std::this_thread::sleep_for(5s);

    timeHandler.stop();
}

TEST(TrustedTimeTest, RDTSCP)
{
    using namespace std::chrono_literals;
    t3e::sgx::EnclaveHandler enclave(ENCLAVE_FILE);
    enclave.ecall<t3e_Test_rdtscp>();

    std::this_thread::sleep_for(5s);
}

TEST(TrustedTimeTest, RDTSC)
{
    using namespace std::chrono_literals;
    t3e::sgx::EnclaveHandler enclave(ENCLAVE_FILE);
    enclave.ecall<t3e_Test_rdtsc>();

    std::this_thread::sleep_for(5s);
}

static inline uint64_t rdtscp(uint32_t& aux)
{
    uint64_t rax, rdx;
    asm volatile("rdtscp\n" : "=a"(rax), "=d"(rdx), "=c"(aux) : :);
    return (rdx << 32) + rax;
}

TEST(TrustedTimeTest, RDTSCPOutside)
{
    std::string a {"Hellaw"};
    t3e_Test_PrintOut(a.data(), a.size());
    uint32_t dummy;
    auto res = rdtscp(dummy);
    std::string str {"Time now: "};
    str.append(std::to_string(res));
    t3e_Test_PrintOut(str.data(), str.size());
}

TEST(TrustedTimeTest, RDTSCOutside)
{
    std::string a {"Hellaw"};
    t3e_Test_PrintOut(a.data(), a.size());
    auto res = __rdtsc();
    std::string str {"Time now: "};
    str.append(std::to_string(res));
    t3e_Test_PrintOut(str.data(), str.size());
}

void SigningTestBySize(size_t dataSizeMultipler)
{
    using namespace std::chrono_literals;
    constexpr uint64_t testCount = 1000;
    size_t dataSize              = 1024 * dataSizeMultipler;

    // Randomize data
    std::vector<uint8_t> data;
    data.resize(dataSize);

    for (int i = 0; i < dataSize; i++)
        data[i] = rand();

    t3e::sgx::EnclaveHandler enclave(ENCLAVE_FILE);

    {
        std::vector<TestEntry> res;
        res.resize(testCount);
        t3e::TrustedTimeHandler timeHandler(enclave, scheme);

        timeHandler.start();
        std::this_thread::sleep_for(3s); // Sleep until trusted time ready
        std::cout << "Enable trusted time\n";
        enclave.ecall<t3e_Test_EnableTrustedTime>();
        std::cout << "Enabled\n";
        auto start = std::chrono::system_clock::now();
        enclave.ecall<t3e_Test_Sign>(data.data(), data.size(), res.data(), res.size());
        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now() - start);
        timeHandler.stop();
        std::vector<TestEntry> delta;

        std::transform(res.begin(), res.end(), std::back_insert_iterator(delta),
                       [&, prev = (TestEntry const*) nullptr](TestEntry const& elem) mutable -> TestEntry
                       {
                           TestEntry ret {elem.seq, 0, 0};
                           if (prev != nullptr)
                           {
                               ret.counterTime = elem.counterTime - prev->counterTime;
                               ret.trustedTime = elem.trustedTime - prev->trustedTime;
                           }

                           prev = &elem;
                           return ret;
                       });

        auto averageTest = std::accumulate(delta.begin(), delta.end(), TestEntry {}) / (delta.size() - 1);

        auto maxTime     = std::max_element(delta.begin(), delta.end(),
                                            [](auto const& a, auto const& b)
                                            {
                                            return a.trustedTime < b.trustedTime;
                                        });

        std::cout << "Test Average: Trusted => " << averageTest.trustedTime << " ms"
                  << ", Counter => " << averageTest.counterTime << std::endl
                  << "Elapsed: " << elapsed << ", average: " << (elapsed / testCount) << std::endl;
    }
}

TEST(TrustedTimeTest, BasicSigning)
{
    uint32_t eax_crystal, ebx_tsc, crystal_hz, edx;
    __cpuid(0x15, eax_crystal, ebx_tsc, crystal_hz, edx);

    std::cout << "Crystal: " << eax_crystal << " " << ebx_tsc << " " << crystal_hz << " " << edx << std::endl;

    for (int i = 128; i < 10240; i *= 2)
    {
        std::cout << "Test: " << i << " ";
        SigningTestBySize(i);
    }
}

TEST(TrustedTimeTest, BasicDelay)
{
    using namespace std::chrono_literals;

    constexpr uint64_t testCount = 100;

    t3e::sgx::EnclaveHandler enclave(ENCLAVE_FILE);

    std::vector<uint64_t> elapsedList;

    // Benchmark first
    for (int i = 0; i < testCount; i++)
    {
        auto start = std::chrono::system_clock::now();
        enclave.ecall<t3e_Test_LongRunningOperations>();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - start);

        elapsedList.push_back(elapsed.count());
    }

    auto avg = std::accumulate(elapsedList.begin(), elapsedList.end(), 0) / elapsedList.size();
    std::cout << "Operation Average: " << avg << " ms" << std::endl;

    // Control
    {
        std::vector<TestEntry> res;
        res.resize(testCount);
        auto start = std::chrono::system_clock::now();
        enclave.ecall<t3e_Test_DelayedTestControl>(res.data(), res.size());
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - start);

        std::cout << "ECALL No TrustedTime Average: " << elapsed / testCount << std::endl;
    }

    t3e::TrustedTimeHandler timeHandler(enclave, scheme);
    simpleDelay = false;

    {
        timeHandler.start();

        std::vector<TestEntry> res;
        res.resize(testCount);
        std::this_thread::sleep_for(2s); // Sleep until trusted time ready

        auto start = std::chrono::system_clock::now();
        enclave.ecall<t3e_Test_DelayedTest>(res.data(), res.size());
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - start);

        std::cout << "ECALL With TrustedTime Average: " << elapsed / testCount << std::endl;

        timeHandler.stop();

        std::cout << "Result:\n";

        std::vector<TestEntry> delta;

        std::transform(res.begin(), res.end(), std::back_insert_iterator(delta),
                       [&, prev = (TestEntry const*) nullptr](TestEntry const& elem) mutable -> TestEntry
                       {
                           TestEntry ret {elem.seq, 0, 0};
                           if (prev != nullptr)
                           {
                               ret.counterTime = elem.counterTime - prev->counterTime;
                               ret.trustedTime = elem.trustedTime - prev->trustedTime;
                           }

                           prev = &elem;
                           return ret;
                       });

        auto averageTest = std::accumulate(delta.begin(), delta.end(), TestEntry {}) / (delta.size() - 1);

        auto maxTime     = std::max_element(delta.begin(), delta.end(),
                                            [](auto const& a, auto const& b)
                                            {
                                            return a.trustedTime < b.trustedTime;
                                        });

        std::cout << "Test Average: Trusted => " << averageTest.trustedTime << " ms"
                  << ", Counter => " << averageTest.counterTime << std::endl;
        std::cout << "Max time: " << maxTime->trustedTime << " ms" << std::endl;
    }
}

struct TimestampRequest
{
    TimestampRequest() {}
    TimestampRequest(uint32_t seq): sequence(seq), sendTime(std::chrono::system_clock::now()) {}
    uint32_t sequence;
    std::chrono::system_clock::time_point sendTime;
    std::optional<std::chrono::system_clock::time_point> processedTime;
    std::optional<std::chrono::system_clock::time_point> receivedTime;
    std::string timestampTime;
};

std::unordered_map<uint32_t, TimestampRequest> requestMap;

extern "C" void t3e_Test_ReceiveTimestamp(uint32_t sequence, const char* buf, size_t bufsize)
{
    auto iter = requestMap.find(sequence);
    if (iter == requestMap.end())
        std::abort();

    auto& [key, req] = *iter;

    req.receivedTime = std::chrono::system_clock::now();

    req.timestampTime = std::string(buf, bufsize);
    
}

TEST(TrustedTimeTest, AccuracyTest)
{
    using namespace std::chrono_literals;

    bool stopping = false;
    std::list<TimestampRequest> requestQueue;

    // Randomize data
    size_t dataSize = 1024 * 8192;
    std::vector<uint8_t> data;
    data.resize(dataSize);

    for (int i = 0; i < dataSize; i++)
        data[i] = rand();

    std::jthread mainThread {[&requestQueue, &data, &stopping]
                             {
                                 t3e::sgx::EnclaveHandler enclave(ENCLAVE_FILE);
                                 t3e::TrustedTimeHandler timeHandler(enclave, scheme);
                                 timeHandler.start();
                                 std::this_thread::sleep_for(3s); // Sleep until trusted time ready
                                 enclave.ecall<t3e_Test_EnableTrustedTime>();

                                 while (!stopping)
                                 {
                                     if (requestQueue.empty())
                                     {
                                         std::this_thread::sleep_for(1ms);
                                         continue;
                                     }

                                     auto& obj      = requestQueue.front();
                                     auto [iter, _] = requestMap.emplace(obj.sequence, obj);
                                     requestQueue.pop_front();

                                     auto& [key, req]  = *iter;
                                     req.processedTime = std::chrono::system_clock::now();
                                     enclave.ecall<t3e_Test_SingleSign>(obj.sequence, data.data(), data.size());
                                 }
                                 timeHandler.stop();
                             }};

    simpleDelay = true;
    std::this_thread::sleep_for(5s);

    // Generate request and put into queue
    for (int i = 0; i < 100; i++)
    {
        requestQueue.emplace_back(i + 1);
        if(i == 0)
            std::this_thread::sleep_for(10s);
        std::this_thread::sleep_for(22ms);
    }

    // Wait until all request has been processed
    for (int i = 0; i < 100;)
    {
        auto iter = requestMap.find(i + 1);
        if (iter == requestMap.end() || !iter->second.receivedTime.has_value())
        {
            i = 0;
            std::this_thread::sleep_for(1ms);
            continue;
        }
        i++;
    }

    stopping     = true;

    auto timeStr = [](auto time)
    {
        auto in_time_t = std::chrono::system_clock::to_time_t(time);

        std::stringstream ss;
        ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X");
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch()) % 1000;
        ss << "." << ms.count();
        return ss.str();
    };

    for (auto& [key, req]: requestMap)
    {
        std::cout << key << ";" << timeStr(req.sendTime) << ";"
                  << timeStr(req.processedTime.value_or(std::chrono::system_clock::time_point {})) << ";"
                  << timeStr(req.receivedTime.value_or(std::chrono::system_clock::time_point {})) << ";" 
                  << req.timestampTime << std::endl;
    }
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}