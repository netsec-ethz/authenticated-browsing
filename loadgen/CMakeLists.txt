CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
project(abgen)

SET(CMAKE_CXX_FLAGS "-fno-stack-protector -Wall -Wextra -Wno-unused-parameter -g -O3 -std=gnu++11 -march=native -I${CMAKE_CURRENT_SOURCE_DIR}/src")
SET(CMAKE_C_FLAGS "-fno-stack-protector -Wall -Wextra -Wno-unused-parameter -g -O3 -std=gnu11 -march=native")

SET(PRJ abgen)

set(files
	abgen.c
)

SET(MOONGEN_DIR /root/moongen)

set_directory_properties(PROPERTIES COMPILE_DEFINITIONS AB_CBCMAC_AESNI)
add_subdirectory(lib/aesni)

# header files for stuff that is available in libmoon
INCLUDE_DIRECTORIES(
	${MOONGEN_DIR}/libmoon/deps/dpdk/x86_64-native-linux-gcc/include
	${MOONGEN_DIR}/libmoon/deps/dpdk/lib/librte_ethdev
	${MOONGEN_DIR}/libmoon/deps/luajit/src
	${MOONGEN_DIR}/libmoon/lib
	${MOONGEN_DIR}/libmoon/src
	lib
)

ADD_LIBRARY(${PRJ} SHARED ${files})
target_link_libraries(${PRJ} PRIVATE aesni)

