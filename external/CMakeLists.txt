execute_process(COMMAND ./bootstrap
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tpm2-tss
                COMMAND_ECHO STDOUT
                ECHO_OUTPUT_VARIABLE)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/tpm2-tss)
execute_process(COMMAND ./configure --enable-debug=yes --enable-static=yes --enable-shared=no --prefix=${CMAKE_CURRENT_BINARY_DIR}/tpm2-tss --disable-log-file --with-maxloglevel=none
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tpm2-tss
                COMMAND_ECHO STDOUT
                ECHO_OUTPUT_VARIABLE)

add_custom_target(TPM2-TSS-Build
                COMMAND make
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tpm2-tss
                COMMENT "Building TPM2-TSS Static Library"
                USES_TERMINAL
                VERBATIM)

add_custom_target(TPM2-TSS
                  COMMAND make install
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tpm2-tss
                  COMMENT "Building TPM2-TSS Static Library"
                  USES_TERMINAL
                  VERBATIM
                  DEPENDS TPM2-TSS-Build)

add_subdirectory(date)

message("-- Configuring external done")
