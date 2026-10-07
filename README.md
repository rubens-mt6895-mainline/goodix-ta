# goodix-ta

Userspace trustlet host for the Goodix gf_spi fingerprint sensor on the Redmi K50
(MT6895, codename rubens), on mainline Linux.

The matching algorithm of this sensor lives in a Goodix TA: a 5.2 MB aarch64 ELF that
the stock firmware runs inside the MediaTek TEE. Mainline has no path into that TEE, so
this host runs the TA as an ordinary userspace process. It loads the ELF, maps it where
the TA expects to be, implements the small set of TEE backed calls the TA makes (about
30 stubs), and bridges the sensor traffic to the kernel driver's `/dev/goodix_fp`
transfer ioctl. Finger templates are kept in `/var/lib/goodixta/*.so`, standing in for
the secure storage the TEE would provide.

With the kernel driver and this host in place the stack works end to end: enrollment
produces a template, verification matches against it, and the lockscreen PAM stack can
authenticate with a finger.

## Status

| item | state |
| --- | --- |
| enrollment | works; one press produces a 57687 byte template |
| verification | works, but the hit rate on our unit is low (2 of 8 presses, about 7 s per attempt) |
| liveness (ASP) | disabled; the sensor presence interrupt (GPIO136) floats and the driver's `finger` attribute never becomes 1, so a capture has to be triggered by the user instead of by a finger present event |
| fprintd | a D-Bus service owns `net.reactivated.Fprint` on the system bus, so the KDE settings panel and `fprintd-*` tools work |

The low hit rate is an open problem. It is not caused by the transport: the SPI path
delivers full 24485 byte frames with about 0.2 percent zero bytes.

## Hardware

| signal | pin |
| --- | --- |
| SPI3_A CLK / CS / MI / MO | GPIO217 / 218 / 219 / 220 |
| reset (active low) | GPIO216 |
| finger present interrupt | GPIO136, rising edge |
| supply | mt6368_vfp, 3.3 V |

The same footprint carries an FPC1540 part on the xaga variants of the board; that one
is fed from mt6368_vibr at 1.8 V.

## Kernel side

The driver is `drivers/misc/goodix_fp.c` plus `include/uapi/linux/goodix_fp.h`, with the
device tree node in `arch/arm64/boot/dts/mediatek/mt6895-xiaomi-rubens.dts` and
`CONFIG_GOODIX_FP=y` in `arch/arm64/configs/rubens.config`. It is a raw transport
bridge: a `/dev/goodix_fp` chardev whose transfer ioctl moves one SPI frame, plus the
reset line and the sensor rail. The trustlet logic stays here in userspace.

All of it is on GitHub:
[rubens-mt6895-mainline/linux](https://github.com/rubens-mt6895-mainline/linux),
branch `7.2-mt6895-xiaomi-rubens` (the driver arrives in commit `889d061a917e`).
See [docs/kernel.md](docs/kernel.md) for the ioctl surface and the device tree node.

## Build

```
make
```

which is:

```
aarch64-linux-gnu-gcc -O2 -static -Wall -Wno-unused-parameter \
    -Wl,-Ttext-segment=0x10000000 -o bin/ta_host src/ta_host.c -lm
```

The linker flag is required. The TA maps itself with `mmap(MAP_FIXED, 0x400000)` and the
host must not be linked into that range. The build prints a few warnings about ignored
`read()` results and unused helper functions; they are harmless but have not been
cleaned up yet.

## Install

```
install -d /opt/goodixta/bin /opt/goodixta/ta /var/lib/goodixta
install -m755 bin/ta_host /opt/goodixta/bin/ta_host
install -m644 bin/goodixfp.ta /opt/goodixta/ta/goodixfp.ta
install -m644 systemd/net.reactivated.Fprint.conf /etc/dbus-1/system.d/
install -m644 systemd/goodix-fprintd.service systemd/goodix-fp-capture.service \
    /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now goodix-fprintd.service

# PAM: merge the three goodix lines from src/common-auth-k50 into
# /etc/pam.d/common-auth. They go after pam_unix so a password still works and
# before the final pam_deny.

fprintd-enroll      # press once per prompt
fprintd-verify
```

`goodix-fp-status.sh`, `goodix-fp-syncslots.sh` and `goodix-fp-restore.sh` are small
maintenance helpers used while debugging enrollments.

## Layout

| path | what |
| --- | --- |
| `src/ta_host.c` | the host: ELF loader, TEE stubs, SPI bridge, storage |
| `src/goodix-fprintd.py` | `net.reactivated.Fprint` service |
| `src/goodix-fp-pam.py` | PAM helper, one capture per login |
| `src/common-auth-k50` | the PAM lines to merge |
| `src/goodix-fp-*.sh` | status, slot sync and restore helpers |
| `systemd/` | units for the service and the capture helper, plus the D-Bus policy |
| `bin/goodixfp.ta` | the vendor TA (see below) |
| `docs/` | architecture and kernel interface notes |

[architecture.md](docs/architecture.md) describes how the host satisfies the TA.

## Provenance of `bin/goodixfp.ta`

It is Goodix's binary, taken from the device's HyperOS system image
(`/vendor/thh/ta/`), and it is redistributed here so that the stack can be rebuilt from
this repository alone. It is not our code and we cannot license it. If you have your
own dump of the same TA, use that file instead.

## Credits

Brought up on a retail Redmi K50 running Debian with a mainline kernel. The kernel
driver, the DT node and this host are maintained in
[rubens-mt6895-mainline](https://github.com/rubens-mt6895-mainline).
