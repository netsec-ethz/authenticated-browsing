cmake_minimum_required(VERSION 3.20)
enable_testing()

find_program(YASM yasm)

add_custom_command(OUTPUT aesnix64asm.o COMMAND ${YASM}
  ARGS -D__linux__ -g dwarf2 -f elf64 -o aesnix64asm.o  ${CMAKE_CURRENT_SOURCE_DIR}/aesnix64asm.s)

add_library(aesni aesnix64asm.o ${CMAKE_CURRENT_SOURCE_DIR}/pmac1.c)
target_include_directories(aesni PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(aesni PROPERTIES LINKER_LANGUAGE C)

############
# pmac1_kat — known-answer tests for PMAC1 against an independent
# reference (openssl AES + textbook Python PMAC1). Locks the algorithm
# down end-to-end through the AES-NI fast paths.
############
add_executable(pmac1_kat EXCLUDE_FROM_ALL test/pmac1_kat.c)
target_link_libraries(pmac1_kat PRIVATE aesni)
add_test(NAME pmac1_kat COMMAND pmac1_kat)