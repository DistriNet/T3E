#include "TrustedTimeHandler.h"
#include <iostream>
#include <vector>
#include <chrono>
#include "chrono_io.h"
#include <locale>
#include <mutex>

#include <SGXHandler.h>

int main()
{
    using namespace std::chrono_literals;
    std::cout << "Begin Trusted Time" << std::endl;

    t3e::sgx::EnclaveHandler enclave("enclave.signed.so");
    t3e::TrustedTimeHandler timeHandler(enclave, t3e::TrustedTimeHandler::ECDSA);
    timeHandler.start();
    
    std::mutex coutMutex;
    /*
    {
        std::vector<std::jthread> threadList;
        for(int i = 0; i < 8; i++)
        {
            threadList.emplace_back([&timeHandler, &coutMutex, i] {
                for(;;)
                {
                    auto [available, trustedTime] = timeHandler.getTrustedTime();
                    std::stringstream ss;
                    if(available)
                    {
                        auto calculatedClock = std::chrono::system_clock::from_time_t(trustedTime / 1000);
                        ss << "Trusted Time at thread " << i  << ": " << calculatedClock << std::endl;
                    }
                    else
                        ss << "Trusted Time not available\n";
                    
                    auto str = ss.str();
                    {
                        std::lock_guard { coutMutex };
                        std::cout.write(str.data(), str.length());
                        std::cout.flush();
                    }
                    std::this_thread::sleep_for(150ms);
                }
            });
        }
    }
    */
    return 0;
}