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
