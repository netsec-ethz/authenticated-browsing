APP=dpdk_forward
SRCS=src/dpdk_forward.c
ASM=lib/aesni/aesnix64asm.s
ASM_OBJ=lib/aesni/aesnix64asm.o
PMAC_SRC=lib/aesni/pmac1.c
PMAC_OBJ=lib/aesni/pmac1.o
AESNI_OBJS=$(ASM_OBJ) $(PMAC_OBJ)
ASM_AS?=yasm
OPENSSL_CFLAGS:=$(shell pkg-config --cflags libcrypto)
OPENSSL_LDFLAGS:=$(shell pkg-config --libs libcrypto)
TEST_HARNESS=tests/test_harness
TEST_SRCS=tests/test_harness.c
PMAC1_KAT=lib/aesni/test/pmac1_kat
PMAC1_KAT_SRCS=lib/aesni/test/pmac1_kat.c
PMAC1_BATCH_TEST=lib/aesni/test/pmac1_batch_test
PMAC1_BATCH_TEST_SRCS=lib/aesni/test/pmac1_batch_test.c

CFLAGS+=-O3 -march=native -Wall -Wextra -Ilib/aesni -Ilib -I. -funroll-loops -fomit-frame-pointer
LDFLAGS+=

# Per-class rx/tx counters. Default build keeps the hot path free of the
# extra branches; enable with:
#     make PER_CLASS_STATS=1
ifeq ($(PER_CLASS_STATS),1)
CFLAGS+=-DAB_PER_CLASS_STATS
endif

PKG_CONFIG?=pkg-config
DPDK_CFLAGS:=$(shell $(PKG_CONFIG) --cflags libdpdk)
DPDK_LDFLAGS:=$(shell $(PKG_CONFIG) --libs libdpdk)

all: $(APP) $(TEST_HARNESS) $(PMAC1_KAT) $(PMAC1_BATCH_TEST)

$(APP): $(SRCS) $(AESNI_OBJS)
	$(CC) $(CFLAGS) $(DPDK_CFLAGS) -o $@ $(SRCS) $(AESNI_OBJS) $(DPDK_LDFLAGS) $(LDFLAGS)

$(ASM_OBJ): $(ASM) Makefile
	$(ASM_AS) -D__linux__ -f elf64 -o $@ $<

$(PMAC_OBJ): $(PMAC_SRC) lib/aesni/pmac1.h Makefile
	$(CC) $(CFLAGS) -c -o $@ $(PMAC_SRC)

$(TEST_HARNESS): $(TEST_SRCS) $(AESNI_OBJS)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ $(TEST_SRCS) $(AESNI_OBJS) $(OPENSSL_LDFLAGS)

$(PMAC1_KAT): $(PMAC1_KAT_SRCS) $(AESNI_OBJS)
	$(CC) $(CFLAGS) -o $@ $(PMAC1_KAT_SRCS) $(AESNI_OBJS)

$(PMAC1_BATCH_TEST): $(PMAC1_BATCH_TEST_SRCS) $(AESNI_OBJS)
	$(CC) $(CFLAGS) -o $@ $(PMAC1_BATCH_TEST_SRCS) $(AESNI_OBJS)

test: $(APP) $(TEST_HARNESS) $(PMAC1_KAT) $(PMAC1_BATCH_TEST)
	./$(PMAC1_KAT)
	./$(PMAC1_BATCH_TEST)
	bash tests/run_tests.sh

clean:
	rm -f $(APP) $(ASM_OBJ) $(PMAC_OBJ) $(TEST_HARNESS) $(PMAC1_KAT) $(PMAC1_BATCH_TEST)

.PHONY: all clean test
