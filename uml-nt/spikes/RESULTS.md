# M0 spike results — Windows runner (GH Actions `windows-latest`, 2026-09-29)

Run: https://github.com/quangdz-comeback/uml-kernel-build/actions/runs/36521049993
(artifact `m0-spike-results`; các run trước giữ lại lịch sử debug)

## Tổng quan — cả 6 spike XANH

| Spike | Câu hỏi | Kết quả | Gate |
|---|---|---|---|
| S1 VEH trap/resume | CONTEXT fidelity + dispatch ns | **p50 1.7µs / p99 2.9µs** (ud2), page-fault p50 2.0µs; 4/4 check đúng (reg-writes stick, RIP redirect, callee-saved survive, fault addr+r/w) | ≤3µs **PASS** |
| S2 cross-process sync | event+section RT; WaitOnAddress scope | spin-protocol p50 **100ns** (both-spin avg 87ns) vs event RT 24.3µs (**~240x**); Interlocked64 coherence OK; **WaitOnAddress cross-proc wake = FALSE (xác nhận trên Windows thật)** | ≤3µs **PASS** |
| S3 ELF launcher | map ET_EXEC + gọi entry trong PE process | **PASS** — payload ghi magic 0xC0FFEE42 vào window cố định 0x50000000 | PASS |
| S4 freestanding ELF | clang+lld trên Windows CI build được kernel-style ELF | PASS (payload.elf build bằng `clang --target=x86_64-linux-gnu` trong MINGW64 CI) | PASS |
| S5 spawn/discard/mapfix | CreateProcess latency hiện đại; DiscardVirtualMemory; fixed-base map child | suspended p50 **1ms**, full p50 **4ms**; discard OK trên private + section view (đọc lại = 0); child map section ở base cố định + parent thấy magic | PASS |
| S6 ud2 scanner | decoder false-positive | payload CI 0/0; xác thực trước đó trên Linux: busybox **302/302, 0 FP**; guest libc 563/565 (2 miss → symtab seeds) | PASS |

## Bài học thiết kế rút ra (đưa vào ARCHITECTURE)

1. **Granularity 64KB là thật và cắn**: 2 VirtualAlloc riêng trong cùng block 64KB
   → ERROR_INVALID_ADDRESS (487). Launcher phải reserve MỘT vùng phủ toàn image
   (round 64KB) rồi mới MEM_COMMIT + VirtualProtect từng segment.
2. **Resume từ VEH phải giữ frame**: redirect RIP sang hàm khác = phải emulate CALL
   (push RIP+2 làm return address); nhảy vào bare-RET sẽ pop return-address của
   caller và unwind cả main. Landing phải là label trong cùng frame.
3. **GCC dead-code NULL-store**: viết `*(volatile int*)0` không điều kiện → GCC
   chứng minh luôn fault, dead-code nhánh sau thành ud2 → resume label bị dời lên
   đầu hàm = vòng lặp vô hạn. Cần điều kiện opaque để giữ fallthrough sống.
4. **Spin cmd-slot phải dedupe theo id đơn điệu** — quan sát lặp trong spin mode
   khiến 1 lệnh chạy nhiều lần (coherence sai trên Windows thật, đúng trên Wine
   vì scheduling chậm che mất). → stub_data protocol dùng monotonic command id.
5. **WaitOnAddress: same-process only — xác nhận thực nghiệm trên Windows**;
   fallback R2 (spin-then-event) không cần thiết ở fast path: p50 100ns đã thấp
   hơn mục tiêu 30 lần. Event vẫn giữ cho wake từ sleep (CPU-idle).
6. **CreateProcess nhanh hơn số liệu cũ** (1ms suspended vs 12–15ms tài liệu 2012)
   → stub pool vẫn đáng làm cho fork-heavy nhưng không phải nút cổ chai.
7. **DiscardVirtualMemory trả về error-code (không phải BOOL)**, chạy được cả trên
   pagefile-section view, trang discard đọc lại = 0 → memdrop-on-free khả thi.

## Số đo đầy đủ

Xem `results/*.json` trong artifact; README.md của spikes mô tả cách chạy local
(MSYS2) và bằng cross-mingw + wine.

---

# M3 results — boot-to-shell (native CI, 2026-09-30)

Run trọn vẹn: https://github.com/quangdz-comeback/uml-kernel-build/actions/runs/36657425722
(M3 kernel+launcher XANH cùng tests 36657425730 + spikes 36657425970)
Gate: "M3.8 S3+S4b+S4c NATIVE INIT-EXEC OK" — chuỗi blob init → execve
/sbin/init → openat/read /hi.sh qua VFS thật → execve /bin/step2 → TLS
(arch_prctl + D18 wrfsbase) → mmap anon → execve /bin/busybox →
**`sh /hi.sh` chạy, `echo hi` + `echo BUSYBOX-SHELL-OK` in bởi busybox SAU
execve** (acceptance grep lọc read-back của init).

## Số đo

| Đại lượng | Giá trị | Ghi chú |
|---|---|---|
| Boot kernel (Memory-line → conn đầu) | ~0.6ms | kernel 65KB/64MB mem=, native runner |
| Memory-line → BUSYBOX-SHELL-OK | **~21ms** | trọn chuỗi exec ×3 + TLS + malloc + sh |
| Launcher wall (spawn → halt → teardown) | ~1.6s | gồm spawn + panic teardown khi exit(0) |
| Syscall RTT quan sát (khi trace bật) | ~60–100µs/round | bị os_info console log làm phình — UPPER bound |
| Syscall dispatch floor (spike S1, VEH ud2) | p50 1.7µs | M0; RTT sạch (không log) = benchmark M4 |
| Rootfs + busybox | 8MB ext4; busybox 131KB static musl | build từ source trong CI, pin sha256 |

## Bài học M3 (đưa vào ARCHITECTURE/STATUS)

1. **`_end` với clang `-mcmodel=large`: orphan `.lbss` đặt SAU `_end`** — real
   bss thành vùng người không sở hữu; `brk_end = UML_ROUND_UP(&_end)` (patch
   0010) trao buddy sở hữu bss SỐNG của kernel → execve busybox (alloc order-0
   đầu tiên) đè anchors deterministic, virt_to_page kế theo bước memmap điên →
   `kmem_cache_free` fault mà mọi đường ubd đều vô tội. Fix: dyn.lds.S gom
   `.lbss/.sbss` trước `__bss_stop` (patch 0016/d204be9). Bài học đôi: (a)
   linker script THẬT của build là `dyn.lds.S` khi `CONFIG_LD_SCRIPT_DYN=y` —
   sửa `uml.lds.S` là no-op; (b) canary biến mất phải suy ra nguyên nhân, không
   ăn mừng trên "hết crash".
2. **Canary D19 = tripwire thường trực**: canary trên os-I/O funnel chỉ anchor
   trash ĐẦU TIÊN (`pread:host fd=1 off=48c000`) — đủ để khoanh vùng cửa sổ
   corruption về exec busybox, và giá trị trash deterministic
   (`physmem=400000001 high=62000200`) chỉ thẳng vào globals bị đè. Kill-reason
   + VMA dump trên FATAL ('why=p') cùng một kiểu: biến quyết định kill thành
   dữ liệu đọc được thay vì đoán.
3. **musl mallocng mở đầu bằng GUARD MAP_FIXED** — `alloc_meta`:
   `brk(0)` → `brk(+2 trang)` → `mmap(brk_base, 4096, PROT_NONE,
   MAP_ANON|MAP_FIXED)` mà **return bị musl bỏ qua**. Kernel-side round 4K →
   64K run TRƯỚC khi check replace → replace nuốt cả heap VMA (NOACCESS + run
   mới) → write meta area tại brk+4K = write fault thật sự trên VMA NOACCESS.
   Fix: sub-run guard trong một VMA run-private = no-op có log (toàn-view stub
   ops không diễn đạt được lỗ 4K trong run sống; geometry VMA = bội run).
4. **Tty driver phải wire `driver->ports[]` TRƯỚC register** — alloc_tty_struct
   copy `driver->ports[idx]` vào `tty->port`; thiếu = WARN "would crash the
   kernel" và writev từ musl stdio (toàn bộ output của busybox) đi qua tty
   KHÔNG port. Probe không thấy vì output probe đi hand-path write(2).
5. **Ash builtin ≠ applet standalone**: `CONFIG_ECHO=y` chỉ bật applet; bên
   trong ash `echo` cần `CONFIG_ASH_ECHO=y` — thiếu = PATH-search `/bin/echo`
   (không có) → "echo: not found" → exit 127 im lặng. Per-syscall trace
   (TEMP) là thứ nêu tên; exit code không đủ.
6. **Trace/diagnostic đọc `d->args` sau exec destroy = fault kernel-native** —
   exec_pending destroy conn (và d) giữa dispatch; MỌI đường sau handler phải
   bail trước khi đụng d (riêng trace này ăn 1 vòng CI vì được đặt trước
   check).
7. **Wine không thể là trọng tài cho exec path** (exec `/sbin/init` -14
   EFAULT deterministic, cả baseline chưa patch) — wine chỉ gate boot/mount;
   exec = native CI. Native CI = source of truth từ S4c1.

## Việc còn mở (M4)

- Benchmark syscall RTT sạch (không log) + throughput; block-wait thật
  (scheduler task), signals M4; multi-run heap growth; page-granular MAP_FIXED
  (guard materialize thật); GUP/rwsem WARN khi wire_args đi gap argv (benign,
  dọn khi làm mm scan).

---

# M4 results — đúng đắn + hiệu năng (native CI, 2026-09-30)

## M4.1 — Syscall RTT sạch + throughput probe nhỏ

Run: https://github.com/quangdz-comeback/uml-kernel-build/actions/runs/36660134234
(gate "NATIVE RTT bench gate (M4.1)", windows-latest; tests 36660134230
+ spikes 36660134290 cùng push `0bca1b0`)

Phương pháp — sạch theo cấu trúc, không phải nhờ lọc log: guest
`/bin/bench` chạy làm PID 1 (`init=/bin/bench` — launcher run riêng,
chuỗi exec POC không bị đụng); 8000 vòng getpid (round rẻ nhất trên
dispatch — thuần bookkeeping, không VFS, không stub ops) giữa 2 marker
console `UMLNT-BENCH-BEGIN`/`UMLNT-BENCH-END` mà kernel nhận ngay
TRONG write handler (khớp chính xác, gate theo độ dài — không đổi
protocol, không syscall mới); vòng lặp `userspace()` THẬT đo từng vòng
wake-to-wake (os_nsecs/QPC) và không log gì mỗi vòng. END in ĐÚNG MỘT
dòng tóm tắt. rdtsc guest chạy native (chỉ `0F 05` bị patch) cho
cross-check cycles.

| Đại lượng | Native (windows-latest) | Wine (local VM — tham khảo) |
|---|---|---|
| Vòng ghi được | 8000/8000 (dropped=0) | 8000/8000 |
| RTT p50 | **26.4µs** | 18.9µs |
| RTT mean | 28.6µs → **eps 35 005 getpid/s** | 24.2µs → eps 41 300 |
| RTT p99 | 83.9µs | 56µs |
| min / max | 1.5µs / 323µs | 7.3µs / 3.96ms |
| Guest cycles | 69 856 cyc/syscall | 74 942 cyc/syscall |
| TSC suy ra (cyc ÷ mean-ns) | ~2.45 GHz | ~3.10 GHz |

Đọc số:
- **p50 26µs ≈ RT event 2 chiều** (S2 đo 24.3µs/RT) — D10 turnstile
  (event cả hai chiều) là floor của đường RTT hiện tại; VEH dispatch
  1.7µs (S1) bị nuốt bên trong. Tối ưu RTT về sau = đường spin-first
  (recipe S2, 100ns) hoặc batch ops — KHÔNG phải tinh chỉnh VEH.
- eps 35k getpid là **trần syscall-bound**; mốc M4 (sysbench ≥ 700 eps
  = 1/3 tham chiếu 2100) còn dải rất rộng so với trần này — đối chiếu
  sysbench thật là bước sau của M4.
- max 323µs = nhiễu scheduler/tick (dữ liệu thô giữ nguyên); p99 ổn
  định. Gate CI khẳng định cấu trúc (rounds=8000, đủ dòng
  cross-check) + trần hợp lý 1ms/headroom 20x — CHƯA PHẢI perf gate.
- WARN GUP/rwsem (wire_args) vẫn hiện trong bench log — đúng dự kiến,
  slice 6 dọn.

Bài học M4.1:
1. Kernel build là `-nostdinc` THẬT SỰ — kể cả `stddef.h`
   compiler-provided cũng không có trên include path của file
   os-Windows; file thuần freestanding phải include-free (NULL tự
   định nghĩa local). Test harness pass KHÔNG chứng minh include path
   kernel — chỉ build vmlinux thật bắt được (1 vòng local, không mất
   vòng CI).
2. Overlay sync khi iterate local: sửa source phải `apply.sh` lại
   trước build — tree cache giữ bản cũ im lặng (không có gì bảo
   "stale").
3. Wine CHẠY ĐƯỢC cả đường exec `init=/bin/bench` (argv-less) tới
   hết bench — EFAULT wine của S4b là ở chuỗi argv-walk; native CI
   vẫn là trọng tài perf.
