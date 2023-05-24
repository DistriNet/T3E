cmake_minimum_required(VERSION 3.18)

project(TPMTime)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
find_package(SGX REQUIRED)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(TPM_LIB_DIR ${CMAKE_BINARY_DIR}/external/tpm2-tss/lib)
set(TPM_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/external/tpm2-tss/include)

set(EDL_SEARCH_PATHS trusted ${TPM_INCLUDE_DIR} include test/delayed-test)

# Change the use count limit here, set INT_MAX if no use count
add_compile_definitions(USE_COUNT_LIMIT=INT_MAX)

include_directories(${TPM_INCLUDE_DIR} include)
link_directories(${TPM_LIB_DIR})

add_subdirectory(external)

set(T3E_ENCLAVE_SRC trusted/T3E-Enclave.cpp)
set(T3E_SRC untrusted/TPMHandler.cpp 
            untrusted/T3E-Untrusted.cpp)
set(LDS trusted/Enclave.lds)

execute_process(COMMAND openssl genrsa -out test_sign_key.pem -3 3072
                WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                COMMAND_ECHO STDOUT
                ECHO_OUTPUT_VARIABLE)


# General standalone T3E Enclave
add_enclave_library(Standalone-T3E-Enclave 
  SRCS ${T3E_ENCLAVE_SRC}
  EDL trusted/T3E-Enclave.edl
  EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
  LDSCRIPT ${LDS}
  USE_SGXSSL)

target_include_directories(Standalone-T3E-Enclave PRIVATE 
  ${TPM_INCLUDE_DIR} 
  include)
target_compile_options(Standalone-T3E-Enclave PRIVATE -include${CMAKE_CURRENT_BINARY_DIR}/T3E-Enclave_t.h)
target_link_directories(Standalone-T3E-Enclave PRIVATE ${TPM_LIB_DIR})
add_dependencies(Standalone-T3E-Enclave TPM2-TSS)
target_link_libraries(Standalone-T3E-Enclave tss2-mu)

enclave_sign(Standalone-T3E-Enclave
  KEY ${CMAKE_CURRENT_BINARY_DIR}/test_sign_key.pem
  CONFIG trusted/Enclave.config.xml)

# 



# # Main function
# add_untrusted_executable(TPMTime SRCS ${SRCS} untrusted/Main.cpp EDL trusted/Enclave.edl EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})
# set_property(TARGET TPMTime PROPERTY CXX_STANDARD 20)
# add_dependencies(TPMTime enclave-sign TPM2-TSS)
# target_link_libraries(TPMTime "-Wl,-Bstatic -ltss2-esys -ltss2-sys -ltss2-mu -ltss2-tcti-device -Wl,-Bdynamic")
# target_link_libraries(TPMTime  ssl crypto)

enable_testing()
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/609281088cfefc76f9d0ce82e1ff6c30cc3591e5.zip
)
FetchContent_MakeAvailable(googletest)
include(GoogleTest)

# # Basic Test



# add_untrusted_executable(TPMTime-Test SRCS ${SRCS} test/BasicTest.cpp EDL trusted/Enclave.edl EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})
# set_property(TARGET TPMTime PROPERTY CXX_STANDARD 20)
# add_dependencies(TPMTime-Test enclave-sign TPM2-TSS)
# target_link_libraries(TPMTime-Test "-Wl,-Bstatic -ltss2-esys -ltss2-sys -ltss2-mu -ltss2-tcti-device -Wl,-Bdynamic")
# target_link_libraries(TPMTime-Test gtest_main ssl crypto)

# gtest_discover_tests(TPMTime-Test)


add_enclave_library(TestSuite-Enclave 
  SRCS ${T3E_ENCLAVE_SRC}
       trusted/TestSuiteEnclave.cpp
  EDL trusted/TestSuiteEnclave.edl 
  EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS} 
  USE_SGXSSL
  LDSCRIPT ${LDS})

target_include_directories(TestSuite-Enclave PRIVATE 
  ${TPM_INCLUDE_DIR} 
  include)
target_compile_options(TestSuite-Enclave PRIVATE -include${CMAKE_CURRENT_BINARY_DIR}/TestSuiteEnclave_t.h)
target_link_libraries(TestSuite-Enclave tss2-mu "-Wl,--wrap=sgxssl_time")
add_dependencies(TestSuite-Enclave TPM2-TSS)
target_compile_definitions(TestSuite-Enclave PRIVATE SGX)

enclave_sign(TestSuite-Enclave 
  KEY ${CMAKE_CURRENT_BINARY_DIR}/test_sign_key.pem 
  CONFIG trusted/Enclave.config.xml)

add_untrusted_executable(T3E-TestSuite 
  SRCS ${T3E_SRC} 
       untrusted/TestSuite.cpp 
  EDL trusted/TestSuiteEnclave.edl 
  EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})

target_compile_options(T3E-TestSuite PRIVATE -include${CMAKE_CURRENT_BINARY_DIR}/TestSuiteEnclave_u.h)
target_compile_definitions(T3E-TestSuite PRIVATE ENCLAVE_FILE="TestSuite-Enclave.signed.so")
set_property(TARGET T3E-TestSuite PROPERTY CXX_STANDARD 20)
add_dependencies(T3E-TestSuite TestSuite-Enclave-sign TPM2-TSS)
target_link_libraries(T3E-TestSuite gtest_main ssl crypto date)
target_link_libraries(T3E-TestSuite "-Wl,-Bstatic -ltss2-esys -ltss2-sys -ltss2-mu -ltss2-tcti-device -Wl,-Bdynamic")
target_link_libraries(T3E-TestSuite "-Wl,--wrap=Esys_GetTime")

gtest_discover_tests(T3E-TestSuite)


# add_executable(TPMTime-TestNoSGX test/delayed-test/TestNoSGX.cpp test/delayed-test/DelayedTestEnclave.cpp)
# set_property(TARGET TPMTime-TestNoSGX PROPERTY CXX_STANDARD 20)
# add_dependencies(TPMTime-TestNoSGX DelayedTest-Enclave-sign TPM2-TSS)
# target_include_directories(TPMTime-TestNoSGX PRIVATE test/delayed-test)
# target_link_libraries(TPMTime-TestNoSGX gtest_main ssl crypto)
# target_link_libraries(TPMTime-TestNoSGX "-Wl,-Bstatic -ltss2-esys -ltss2-sys -ltss2-mu -ltss2-tcti-device -Wl,-Bdynamic")
# gtest_discover_tests(TPMTime-TestNoSGX)
# target_link_libraries(TPMTime-TestNoSGX "-Wl,--wrap=Esys_GetTime")
