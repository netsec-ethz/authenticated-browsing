# AuthBrowsing-dpdk

A DPDK-based optimized prototype for line-rate validation of Authenticated Browsing
IPv6 packets, plus a MoonGen-based load generator that produces the matching traffic
mix.

The validator parses an IPv6 destination-options header carrying a MAC tag
and forwards (or drops) packets based on the result. The loadgen builds the
same packet format and can mix legitimate, malformed, forged, and replayed
classes for benchmarking.

## Layout

- [validator/](validator/) — DPDK validator with duplicate detection and AES-NI MAC 
  verification on the hot path.
- [loadgen/](loadgen/) — MoonGen scripts and a C helper library for building
  authenticated packets at line rate.

## Building

Validator (needs DPDK, yasm, a C toolchain). For a detailed overview of which
dependencies are necessary, please look at a `setup-host.sh` script for a `filter` 
in the associated `authenticated-browsing-eval` repo, which sets a machine up from 
scratch.

```
cd validator
make            # builds dpdk_forward, the test harness, and the PMAC1 KAT
make test       # runs known-answer tests + integration tests
```

Per-class RX/TX counters are off by default.
Enable with `make PER_CLASS_STATS=1`.

Load generator (needs MoonGen, OpenSSL, yasm). For a detailed overview of which
dependencies are necessary, please look at a `setup-host.sh` script for a `lg` 
in the associated `authenticated-browsing-eval` repo, which sets a machine up from 
scratch.

```
cd loadgen && mkdir -p build && cd build
cmake .. && make -j
/path/to/MoonGen ../abgen.lua 0
```

## Config

Keys and MAC parameters live in [validator/config/](validator/config/)
(`keys.json`, `mac.conf`).
