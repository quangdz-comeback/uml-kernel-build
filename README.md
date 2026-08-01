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

### Networking config (`config.yaml`)

`vde_plug` reads `config.yaml` from **its own directory** (resolved via
`/proc/self/exe`, so finding the binary through `PATH` still works). See
`slirp.yaml` in this repo for a fully commented template.

Note that UML locates the helper with `execvp("vde_plug")` — the path in
`vnl=` is *not* used for that. The binary's directory must be in `PATH`:

```bash
export PATH="$PWD:$PATH"
```

#### Private network between instances

With `switch: true` (the default) every instance sharing one socket lands on
a single L2 segment. The first instance to bind the socket becomes the **hub**
and runs the uplink (slirp NAT or a host tap); later instances are **peers**,
plain wires into the hub. The hub is a MAC-learning switch, so unicast between
two guests does not hit the others.

Because one DHCP server now serves the whole segment, guests receive
**distinct leases** — `10.0.2.15`, `.16`, `.17`, … — instead of every instance
claiming `.15`. Nothing needs to be configured per instance.

Socket path resolution, in order:

1. `socket:` in `config.yaml`
2. `$VDE_SWITCH_SOCKET`
3. `/tmp/vde.socket` — the shared default
4. `$TMPDIR/vde.socket`
5. `<binary dir>/vde.socket`

Steps 4–5 matter in sandboxes such as Pterodactyl where `/tmp` is missing or
read-only. The resolved path is printed on the status line. A leftover socket
file from a crashed hub is reclaimed automatically (`connect()` is tried before
`bind()`, so a live hub is never disturbed).

Set `switch: false` for the classic one-NAT-per-instance behaviour.

#### Uplink modes

| `uplink:` | Behaviour |
|---|---|
| `slirp` | Userspace NAT, no privileges. Default. |
| `tap:NAME` | Attach to an existing host tap. DHCP comes from the real LAN, so guests get real addresses — this is the Proxmox/bridged case. Needs `/dev/net/tun`; falls back to slirp if unavailable. |
| `none` | Isolated segment: guest-to-guest only, no internet. |

The tap must already exist and be enslaved to the bridge (e.g. `vmbr0`);
`vde_plug` only opens it.

#### Port forwarding

```yaml
portfwd: true
ports:
  - 2222:22        # host:guest, TCP by default
  - 8080:80
  - udp 5353:53
```

Rules target the first DHCP lease (`dhcp_start`). Only the hub publishes
forwards, since only the hub owns the slirp stack.

---

## 4. Notes

* You can use any Linux Cloud Image compatible with UML.
* Adjust `mem` parameter according to your host's available RAM.
* SLIRP allows network access without needing root privileges.
* `init=/sbin/init` works for both systemd and OpenRC guests.


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


### `uml-memdrop-on-free.patch`

`memfd` stops host writeback, but host RSS still tracks the guest high-water
mark because physmem is one long `MAP_SHARED` mapping.

This patch registers UML with the kernel **PAGE_REPORTING** framework (same
machinery virtio free-page reporting uses). When enough free buddy pages of
a given order accumulate, mm isolates them (they cannot be allocated), calls
our reporter which `MADV_REMOVE`s the host backing, then returns them to the
freelist. Guest free-count is unchanged; host RSS shrinks; next touch
zero-faults.

This avoids the traps of naive approaches:

* delayed punch of a just-freed address → use-after-reuse
* punching a random `alloc_page` → wrong pages (cold freelist)
* fixed PFN queue → overflows on large munmap

Default is **batch**, not per-4K free-path syscalls:

* `memdrop=batch` (default) — report free pages of order ≥ **3** (~32KiB)
* `memdrop=on` — order ≥ **0** (framework still batches into scatterlists)
* `memdrop=<order>` — custom minimum free order
* `memdrop=off` — disabled

Requires `CONFIG_PAGE_REPORTING=y` (enabled in `containers.config`).


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

## Container support (Docker / Podman / LXC)

`patches/containers.config` is merged into every kernel build, then the
workflow re-asserts critical knobs with `scripts/config` so unknown symbols
on older LTS do not silently drop features. Enabled primitives:

* **Namespaces** — `user/pid/net/ipc/uts/cgroup` (userns for rootless).
* **Cgroup v2** — controllers including `memory/cpu/io/pids/device/cpuset`,
  plus `FAIR_GROUP_SCHED` / `CFS_BANDWIDTH` / freezer / cpuacct / BPF.
  Mount v2 in the guest:

  ```bash
  mount -t cgroup2 none /sys/fs/cgroup
  echo "+memory +cpu +pids +cpuset" > /sys/fs/cgroup/cgroup.subtree_control
  ```

  (systemd does this automatically.)
* **Seccomp-filter** — hard-required by Docker/Podman.
* **Checkpoint/restore** — `CHECKPOINT_RESTORE` for CRIU-style tooling.
* **Networking** — `veth`, `bridge`, `bridge-nf`, `macvlan`, `ipvlan`, `tap`,
  full netfilter/iptables (+ ip6tables) for publish-port NAT.
* **Storage** — `overlay2` (overlayfs), `fuse`, `fhandle`, ext4 POSIX ACL +
  security xattrs.
* **memdrop** — `PAGE_REPORTING=y` (pairs with `uml-memdrop-on-free.patch`).

### UML-specific caveats

1. **No loop device** (`/dev/loop*`) — Docker's loopback/devicemapper
   storage won't work. Use **overlay2** on a raw `ubd` backing file.
2. **No host TAP** — `veth`/`bridge` work *inside* the guest for
   container↔container traffic, but egress to the host goes through UML's
   own vector/slirp transport, not a host bridge.
3. **No KVM/hardware virt** — nested containers run as plain user-space
   (not nested VMs).

### Verified at runtime (6.18.38 + SMP + container config)

```
smp: Brought up 1 node, 2 CPUs
/sys/fs/cgroup/cgroup.controllers: cpu io memory pids misc
unshare --user --mount --pid --net --fork: NS_OK
ip link add veth0 type veth peer veth1: ok
ip link add br0 type bridge: ok
```
