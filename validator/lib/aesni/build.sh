#!/usr/bin/env bash
set -Eeuo pipefail

rm -f *.o libaesni.a
yasm -D__linux__ -g dwarf2 -f elf64 aesnix64asm.s -o aesnix64asm.o
${CC:-cc} -O3 -march=native -c pmac1.c -o pmac1.o
ar cr libaesni.a aesnix64asm.o pmac1.o
