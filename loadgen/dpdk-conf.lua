-- Four physical DPDK ports + TAP vdev on pikachu, with explicit EAL -a
-- entries via cli (so pciWhitelist precedence isn't a worry).
-- Port indices: 0=05:00.1, 1=07:00.1, 2=81:00.0, 3=88:00.1, 4=net_tap0 (wrkout).
DPDKConfig {
    cli = {
        "-a", "0000:05:00.1",
        "-a", "0000:07:00.1",
        "-a", "0000:81:00.0",
        "-a", "0000:88:00.1",
        "--vdev", "net_tap0,iface=wrkout,mac=02:99:99:99:99:99",
    },
}
