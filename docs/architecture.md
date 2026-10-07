# How the host satisfies the trustlet

The Goodix TA is not written to run in userspace. It is an aarch64 ELF that the stock
firmware loads into the MediaTek TEE, and it expects the services of that environment.
`src/ta_host.c` provides just enough of them:

1. **ELF loading.** The host maps the TA's segments and applies its relocations. The TA
   maps a region of its own with `mmap(MAP_FIXED, 0x400000)`, so the host must not be
   linked anywhere near that address; the Makefile passes
   `-Wl,-Ttext-segment=0x10000000` for this reason. Linking at `0x400000` (the default
   for a static binary) makes the TA's own mapping collide with the host and the process
   dies immediately.
2. **TEE stubs.** The TA's calls into the trusted environment are answered by roughly
   thirty stubs in the host: session open and close, shared memory allocation, command
   dispatch, and the storage calls the TA makes for its templates and firmware blobs.
   The stubs are the reason this works at all; the protocol on the wire is the TA's own.
3. **Sensor transport.** When the TA wants to talk to the sensor it calls the platform's
   SPI primitive, which the host services with `GOODIX_FP_IOC_RAW_XFER` on
   `/dev/goodix_fp`. The kernel driver moves one frame per call. A large frame from this
   sensor is about 24485 bytes.
4. **Trusted storage.** The TEE would keep the TA's data in secure storage. The host
   writes it to `/var/lib/goodixta/<name>.so` instead, which is why that directory must
   exist and must be writable by the service. An enrolled finger is one such file, 57687
   bytes for the template we measured.

The TA also calls into its own platform layer for the reset line, the rail and timing,
which is why the driver owns those three resources rather than the host.

## Bringing a session up

`goodix-fprintd.service` owns `net.reactivated.Fprint` on the system bus so that the
KDE settings panel and the `fprintd-*` command line tools work unmodified. It runs the
host, which loads the TA and answers its calls. Enrollment prompts for a press, the TA
builds the template and the host stores it. Verification prompts for a press, the TA
compares it against the stored template and returns a match or a mismatch.

`goodix-fp-pam.py` is the other entry point. `pam_exec` runs it once during login, it
takes a single capture and returns success or failure, and the PAM stack falls back to
the password. See `src/common-auth-k50` for the lines to merge and README.md for the
order they belong in.

## Debugging

Failures in this stack show up as the TA refusing to start (usually a mapping or a stub
the TA did not expect to be missing) or as a capture that never matches. `ta_host`
installs a `SIGSEGV` handler that prints the faulting registers, which is the first
thing to look at. `goodix-fp-status.sh` prints the state of the service, the slots and
the last capture; `goodix-fp-syncslots.sh` and `goodix-fp-restore.sh` repair the stored
templates when an enrollment was interrupted.
