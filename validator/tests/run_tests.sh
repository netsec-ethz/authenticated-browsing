#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAP_IFACE="dpdk_test0"
DEFAULT_KEY="00000000000000000000000000000000"
ALT_KEY="0123456789abcdeffedcba9876543210"
ALT_DEST="2001:db8::ff"
DST_MAC="02:00:00:00:00:02"

TEST_CONFIG_DIR="${ROOT_DIR}/tests/config"
DPDK_PID=""

cleanup() {
    if [[ -n "${DPDK_PID}" ]]; then
        echo "[test] stopping dpdk_forward (pid ${DPDK_PID})"
        kill "${DPDK_PID}" 2>/dev/null || true
        wait "${DPDK_PID}" 2>/dev/null || true
    fi
    rm -rf "${TEST_CONFIG_DIR}"
}
trap cleanup EXIT

# --- Hugepages ---
if ! mount | grep -q hugetlbfs; then
    echo "[test] mounting hugetlbfs"
    mkdir -p /mnt/huge
    mount -t hugetlbfs nodev /mnt/huge
fi
if [[ -w /proc/sys/vm/nr_hugepages ]]; then
    CURRENT_HP=$(cat /proc/sys/vm/nr_hugepages)
    if (( CURRENT_HP < 256 )); then
        echo 256 > /proc/sys/vm/nr_hugepages
    fi
fi

# --- Build ---
echo "[test] building..."
make -C "${ROOT_DIR}" 2>&1 | tail -5

# Build test harness
echo "[test] building test_harness..."
OPENSSL_CFLAGS=$(pkg-config --cflags libcrypto 2>/dev/null || true)
OPENSSL_LDFLAGS=$(pkg-config --libs libcrypto 2>/dev/null || echo "-lcrypto")
cc -O2 -Wall -Wextra -I"${ROOT_DIR}/lib/aesni" -I"${ROOT_DIR}/lib" -I"${ROOT_DIR}" \
    ${OPENSSL_CFLAGS} \
    -o "${ROOT_DIR}/tests/test_harness" \
    "${ROOT_DIR}/tests/test_harness.c" \
    "${ROOT_DIR}/lib/aesni/aesnix64asm.o" \
    "${ROOT_DIR}/lib/aesni/pmac1.o" \
    ${OPENSSL_LDFLAGS}

# --- Test config ---
mkdir -p "${TEST_CONFIG_DIR}"

cat > "${TEST_CONFIG_DIR}/mac.conf" <<EOF
# Test destination MAC
mac=${DST_MAC}
EOF

cat > "${TEST_CONFIG_DIR}/keys.json" <<EOF
{
  "default": "${DEFAULT_KEY}",
  "${ALT_DEST}": "${ALT_KEY}"
}
EOF

echo "[test] test config:"
echo "  default key: ${DEFAULT_KEY}"
echo "  alt key for ${ALT_DEST}: ${ALT_KEY}"
echo "  dst mac: ${DST_MAC}"

# --- Start dpdk_forward with virtual tap interface ---
echo "[test] starting dpdk_forward with tap vdev (${TAP_IFACE})..."

SINGLE_MODE= "${ROOT_DIR}/dpdk_forward" \
    --no-telemetry --no-pci \
    --vdev="net_tap0,iface=${TAP_IFACE}" \
    -l 0 \
    -- -c "${TEST_CONFIG_DIR}/mac.conf" -k "${TEST_CONFIG_DIR}/keys.json" \
    > "${ROOT_DIR}/tests/dpdk_forward.log" 2>&1 &
DPDK_PID=$!

echo "[test] dpdk_forward pid: ${DPDK_PID}"

# Wait for the tap interface to appear
echo -n "[test] waiting for ${TAP_IFACE} to appear..."
for i in $(seq 1 30); do
    if ip link show "${TAP_IFACE}" >/dev/null 2>&1; then
        echo " ok (${i}s)"
        break
    fi
    if ! kill -0 "${DPDK_PID}" 2>/dev/null; then
        echo " FAILED (dpdk_forward exited)"
        echo "[test] dpdk_forward log:"
        cat "${ROOT_DIR}/tests/dpdk_forward.log"
        exit 1
    fi
    sleep 1
done

if ! ip link show "${TAP_IFACE}" >/dev/null 2>&1; then
    echo " FAILED (timeout)"
    echo "[test] dpdk_forward log:"
    cat "${ROOT_DIR}/tests/dpdk_forward.log"
    exit 1
fi

# Bring the interface up
ip link set "${TAP_IFACE}" up
ip -6 addr add "2001:db8::100/64" dev "${TAP_IFACE}" 2>/dev/null || true

# Give dpdk_forward a moment to start polling
sleep 1

# --- Run tests ---
echo "[test] running test harness..."
echo ""

"${ROOT_DIR}/tests/test_harness" \
    --iface "${TAP_IFACE}" \
    --key "${DEFAULT_KEY}" \
    --alt-key "${ALT_KEY}" \
    --alt-dest "${ALT_DEST}" \
    --dst-mac "${DST_MAC}"
TEST_RC=$?

echo ""
if [[ ${TEST_RC} -eq 0 ]]; then
    echo "[test] ALL TESTS PASSED"
else
    echo "[test] SOME TESTS FAILED (see above)"
fi

echo "[test] dpdk_forward log (last 20 lines):"
tail -20 "${ROOT_DIR}/tests/dpdk_forward.log"

exit ${TEST_RC}
