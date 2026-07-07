# UML Kernel + SLIRP + Linux cloud images

This guide shows how to boot an **User-Mode Linux (UML)** kernel with a Linux cloudimg using **SLIRP** for network connectivity.

---

## 1. Prerequisites

Make sure you have in the same directory:

- `linux` → UML kernel binary
- `slirp` → static SLIRP binary
- `disk.img` → Any Linux cloudimg

---

## 2. Boot UML

Run the following command from the directory containing the files:

```bash
./linux \
    mode=skas0 \
    mem=2048M \
    ubd0=disk.img \
    root=/dev/ubda1 \
    rw \
    init=/lib/systemd/systemd \
    eth0=slirp,,./slirp \
    con0=fd:0,fd:1 \
    con=null
````

### Explanation of key options:

* `mode=skas0` → required for SKAS0 mode for UML
* `mem=2048M` → allocate 2GB memory to the guest
* `ubd0=...` → the root filesystem image
* `root=/dev/ubda1 rw` → use first partition (partition 1) of UML disk as root, read-write mode
* `init=/lib/systemd/systemd` → start systemd as init
* `eth0=slirp,,./slirp` → connect guest `eth0` to SLIRP for network
* `con0=fd:0,fd:1` → console attached to current terminal
* `con=null` → disable other consoles

---

## 3. Setup Networking inside UML

Once inside the UML guest, configure the network to access the internet:

```bash
# Configure eth0 IP and bring it up
ip a add dev eth0 10.0.2.1
ip l set eth0 up

# Set default route
ip r add default dev eth0

# Configure DNS
echo "nameserver 10.0.2.3" > /etc/resolv.conf
```

After this, the guest should be able to access the internet via SLIRP.

For port forwarding, create a file named `slirp_config` in same folder and add forwarded port in format `[guest_port]:[host_port]` like this:
```
22:2222
80:8080
...
```

---

## 4. Notes

* You can use any Linux Cloud Image compatible with UML.
* Adjust `mem` parameter according to your host's available RAM.
* SLIRP allows network access without needing root privileges.


---

## 5. Bundled kernel patches (`patches/`)

Every kernel-build workflow applies all `patches/*.patch` on top of the
released tarball before configuring. Patches are authored against the latest
LTS but use minimal context so they forward/back-port cleanly.

### `uml-physmem-memfd.patch`

By default UML backs the entire guest "physical" memory with an unlinked
tempfile created in `$TMPDIR` (falling back to `/dev/shm`, then `/tmp`). On a
host where the tempdir is **not** tmpfs-backed, those pages become regular
file-backed dirty pages and are throttled by the host's `vm.dirty_ratio`,
which noticeably degrades guest performance.

This patch makes `create_mem_file()` prefer an anonymous **`memfd_create()`**
file descriptor for physmem. The memfd is backed by the kernel's internal
shmem/tmpfs, so guest RAM pages are never written back to a real device,
regardless of whether the host has a usable tmpfs tempdir. If `memfd_create`
is unavailable (very old host kernels) it falls back to the original
on-disk tempfile. This mirrors the exact pattern already used by UML's own
stub-executable allocator (`init_stub_exe_fd` in `arch/um/os-Linux/skas/process.c`).

**Result:** the guest boots and runs at full speed even when `TMPDIR` points
at a plain on-disk directory (verified: guest memory shows as
`/memfd:uml-physmem (deleted)` and the tempdir stays empty).

### UML SMP support (`patches/apply-smp.sh`, `patches/smp-backport/`)

Upstream UML was single-CPU for its entire history until **v6.19** (Oct 2025),
which landed the initial SMP support (commit `1e4ee5135d81` by Tiwei Bie).
6.18 LTS — the current LTS — predates that and will never get SMP natively.

This repo bridges that gap:

* **Kernel ≥ 6.19** — native SMP; `apply-smp.sh` is a no-op, only
  `CONFIG_SMP=y NR_CPUS=64` is enabled in the build config.
* **Kernel 6.18.x** — the full upstream SMP series (20 commits, base
  6.18-rc3) is backported. `apply-smp.sh` applies the cumulative patch via
  `git apply --3way` (falls back to `patch --fuzz=3`), which survives minor
  context drift as 6.18.x stable backports accumulate. Series applies
  cleanly to 6.18.37/6.18.38 and builds/boots verified.
* **Kernel ≤ 6.17 (incl. 6.12 LTS)** — the series base is too far away to
  port safely; SMP stays off and the kernel boots single-CPU as upstream.

To actually use multiple vCPUs, boot with:

```bash
./linux mem=2G ncpus=8 seccomp=on ...   # up to NR_CPUS (64) vCPUs
```

`ncpus=N` sets how many vCPUs to start; `seccomp=on` is **required**
(SMP is incompatible with the default PTRACE userspace mode and will refuse
to boot without it). Each vCPU is a host thread.

Note: with SMP enabled, UML userspace stubs remain single-threaded per
process — kernel-mode execution and kthreads are parallel, but userspace
threads of a single process still serialize within that process's stub.
This is an upstream limitation of the initial SMP support.
