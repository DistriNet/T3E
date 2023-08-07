# T3E
TPM-based Trusted Time Extensions (T3E) is a novel solution that leverages TPM functionality to provide trusted time services in Intel SGX enclaves while protecting against common attacks. Previous versions of the SGX SDK provided the `sgx_get_trusted_time` function as an alternative to OS time. However, Intel removed the API in 2020 without providing an alternative. T3E leverages TPM functionality to provide trusted time services in enclaves while protecting against common attacks. It offers better time granularity and lower latency than Intel's `sgx_get_trusted_time` implementation. Unlike related work, it does not rely on deprecated features or hardware/firmware modifications.

## Building

Currently, T3E is only tested on Linux machines. However, porting it to Windows with potentially some modifications is possible.

### Requirements
CMake, Clang, and C++ toolchain
Intel SGX SDK (https://github.com/intel/linux-sgx)
Intel SGX OpenSSL (https://github.com/intel/intel-sgx-ssl)

### How to Build

Run the CMake script, build everything, run the test project :)

## Cite Our Paper:
T3E: A Practical Solution to Trusted Time in Secure Enclaves (https://doi.org/10.1007/978-3-031-39828-5_17)
