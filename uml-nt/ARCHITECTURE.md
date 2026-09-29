# ARCHITECTURE — uml-nt: quyết định kiến trúc (HANDOFF §10)

Quyết định kiến trúc lớn ghi ở đây, đánh số D. Các quyết định D1–D10
nằm trong research notes (repo nghiên cứu); file này bắt đầu lại từ
D11 trong tree chính.

## D11 — Trang guest PHẢI đến từ kernel page allocator (2026-09-29)

**Quyết định:** mọi trang guest (run 64K cho per-VMA views, COW copies,
sau này ELF loader) cấp qua `alloc_pages(GFP_KERNEL, order)` — kernel
buddy allocator — KHÔNG BAO GIỜ qua allocator riêng tự quản vùng
section. physalloc chỉ là lớp refcount trên buddy
(skas/physbackend.c = backend; unref về 0 = `__free_pages`).

**Bối cảnh (root cause M3.3):** allocator riêng `probe_phys` cấp 64K-runs
từ image_end trở đi, trong khi buddy/slab của kernel quản lý CÙNG vùng
đó (`arch_mm_preinit` chỉ đặt `min_low_pfn = PFN_UP(__pa(uml_reserved))`
— loại image, không biết runs của ta). Hai allocator cùng trao một trang:
guest viết vào run (guard write, mm_clone eager copy, child text
self-write) đập SLUB metadata/maple node → freelist rác → kernel chết
SAU probe: `kmem_cache_alloc` deref NULL-cache và
`mtree_load(&sparse_irqs)` node rác `0xffffff00` từ `deliver_alarm`
(sigqueue alloc — timer là thread cấp phát bận rộn nhất). Điểm rơi KHÔNG
xác định (mỗi run một chỗ khác nhau) — đặc trưng corruption.

**Hệ quả thiết kế:**
- Offset run = `page_to_pfn(pg) << PAGE_SHIFT` — ĐỘNG. Không code nào
  được giả định layout cố định trên image (không burn runs, không
  `alloc_at(offset cố định)`, không guard-VA tính theo delta từ entry).
- VMA 1 run: đơn giản (single-run luôn contiguous). VMA ĐA run cần
  cấp PHÂN ĐOẠN contiguous từ buddy (một `MapViewOfFileEx` phủ cả
  VMA) — chốt ở D12.
- Ràng buộc NT giữ nguyên (mm_clone): VMA giữ rsp phải eager-copy lúc
  fork — VEH dispatch đẩy exception frame lên stack bị fault, trang
  COW-RO giết dispatch trước khi handler chạy.
- Giả định identity `va == RAM_BASE + run_off` chỉ đúng cho run CHƯA
  bị COW-copy; syscall translate (write/…, M3.7) phải đi qua VMA tree
  (`va → vma → run_off + (va - start)`), không trừ thẳng ram_base.

## D12 — Span đa-run = block buddy order cao; block chỉ free khi MỌI run refs=0 (2026-09-29)

**Quyết định:** VMA đa-run (segment ELF, stack — M3.4 loader) lấy
contiguity từ chính buddy: `uml_nt_phys_alloc_span(ph, nruns)` →
`alloc_pages(GFP_KERNEL|__GFP_ZERO, RUN_ORDER + ceil_log2(nruns))` —
block buddy cấp nguyên khối là contiguous by construction. Không
thêm allocator, không drán runs rải rác rồi hy vọng kề nhau. Refcount
vẫn tính per-run (mm context claim từng run); block backend chỉ được
`__free_pages` khi **mọi** run của block đều refs=0 (scan block từ
owner run — `span_len`/`span_back` per run).

**Vì sao free-theo-block:** COW split tách VMA theo run — các piece
flank vẫn tham chiếu run cũ của block. Free ngay khi owner run
refs=0 (logic cũ) = rút backing sống dưới chân piece flank →
use-after-free (chạm được thật: parent drop sớm hơn child sau khi
child đã copy-out một run). Scan-all-runs trước khi free là điều kiện
đúng duy nhất.

**Hệ quả:**
- Over-allocation được chấp nhận (block 2^k ≥ nruns; padding run nằm
  trong block, buddy không rehand — refcount layer không track
  padding).
- VMA mới sau loader: `uml_nt_elf_load` tạo một VMA per vùng load
  (segments cùng run bị MERGE: union flag bits → `prot_from_flags` —
  OR trực tiếp PAGE_* không hợp lệ, NT PAGE_* không phải lattice).
- ET_DYN chọn base first-fit trên các VMA có sẵn từ RAM_BASE (PIE
  analogue) — hỏi mm, không đoán vị trí.
- Stack guest do loader đặt: 1 run ngay trên region cao nhất
  (`uml_nt_elf_stack_place`) — stack thuộc về image đang nạp, không
  đụng vùng có sẵn.
- Nguồn ảnh guest (M3.4): launcher path — `uml_nt_exec=<file>` trên
  cmdline, launcher đọc file nạp vào section, đưa handle qua
  boot-info v2 (`exec_section`/`exec_size`, append-only). Kernel map
  view read-only ở VA cố định 0x0C000000 (dưới block stub_data
  0x10000000 — cùng lý do cố định-VA như stub bootstrap), parse,
  copy vào runs, unmap. Rootfs thật (M3.5 ubd) sẽ thay nguồn này.
- Guard-VA cho probe truyền qua r12/r13 (callee-saved, init_regs) —
  hết slot-patch theo offset tuyệt đối trong blob (D11: không có VA
  cố định nào để patch cả).

## D13 — ubd đồng bộ, không io thread; fd table NT cho host files (2026-09-29)

**ubd trên os-Windows chạy đồng bộ, không io thread.** Upstream 6.18
ubd chạy mọi I/O qua helper thread + pipe (`start_io_thread` → os_pipe
+ poll). NT backend không có pipe poll-able (`os_pipe` PANIC), và
overlapped I/O là bài toán M4 — nên `os-Windows/ubd_user.c` trả
`-ENOSYS` từ `start_io_thread`; upstream `ubd_driver_init` tiếp nhận
gracefully ("falling back to synchronous I/O") nhưng 6.18 submit path
LUÔN ghi request vào thread_fd — với thread_fd=-1 request bị retry mãi
(BLK_STS_DEV_RESOURCE → mount treo). Patch 0012 thêm nhánh
`thread_fd < 0` chạy `do_io()` ngay trong queue_rq +
`blk_mq_end_request` (chấp nhận được: vCPU đang chờ request này, timer
alarm là NT thread riêng vẫn tick). Patch 0013 bỏ `:` khỏi separator
của ubd cmdline — "Z:\..." bị upstream tách nhầm thành COW layer (kẻ
địch là dấu hai chấm của drive DOS).

**os_file cho host files = fd table NT nhỏ (16 slot), I/O đồng bộ
explicit-offset.** `os_open_file` → NtCreateFile
(FILE_SYNCHRONOUS_IO_NONALERT), fd = index vào table {handle, pos};
pread/pwrite truyền LARGE_INTEGER offset thẳng vào
NtReadFile/NtWriteFile; stream read/write giữ pos trong table
(os_seek_file = ghi bookkeeping). Giá trị POC, ghi rõ trong file.c:
`os_sync_file` = no-op (crash có thể mất đuôi write), `os_lock_file` =
no-op (single-instance), falloc_punch/zeroes trả `-EOPNOTSUPP` —
upstream tự `blk_queue_disable_discard` qua map_error (degrade đúng
đường có sẵn, không fork code).

**COW: khai unsupported.** `CONFIG_BLK_DEV_COW_COMMON` default =y theo
UBD, nhưng cow_user.c upstream là libc-host code (unistd/arpa/inet) —
không thể build dưới D1. Năm symbol COW được stub trong
`os-Windows/ubd_user.c`: `read_cow_header` trả `-EINVAL` (đúng
semantics "plain file" upstream), phần còn lại stub_panic (không
reachable).

**drivers/ build chọn lọc.** Patch 0004 cho `drivers/` vào build lại
dưới OS_WINDOWS; patch 0011 viết lại drivers/Makefile: nhánh
OS_WINDOWS chỉ build `ubd.o = ubd_kern.o` (user side từ os-Windows/),
nhánh còn lại giữ nguyên upstream. Lưu ý: CONFIG_MCONSOLE và
CONFIG_STDERR_CONSOLE mặc định =y — phải tắt MCONSOLE trong defconfig
(mconsole_kern.h có sẵn no-op cho !CONFIG_MCONSOLE) và nhánh
OS_WINDOWS không được phép leak các obj-$ đó.

**Gate M3.5** (không cần console/tty): rootfs.ext4 8MB chứa
/sbin/init static freestanding (viết syscall thẳng, exit 42), build
bằng `mke2fs -d` (không cần root/loop). Boot grep hợp đồng:
`EXT4-fs (ubda): mounted filesystem` + `VFS: Mounted root (ext4
filesystem)` + `Run /sbin/init as init process`; boot sau đó park
trong stub_panic start_userspace (việc M3.7/M3.8) → timeout 124 =
"đã tới cuối đường". devtmpfs mount báo `error mounting -2` — ghi
nhận, xử lý cùng M3.8 (busybox cần /dev).

## D14 — Console TTY = tty_driver thật + seam stdio handles, không port chan/line (2026-09-29)

**Console M3.6 là driver thật nhưng không port stack chan/line của
upstream.** Upstream 6.18: stdio_console + line + chan (~1900 dòng)
— phần generic (tty core, line discipline, flip buffers) KERNEL đã
có sẵn (CONFIG_TTY=y); phần riêng của UML (chan layer) là fd/poll
shaped — thứ NT backend không có (os_pipe PANIC, overlapped là M4).
Port chọn lọc trong `os-Windows/console.c`:
- **1 tty_driver (major 4, /dev/tty0) trên 1 tty_port**: ops
  open/close = `tty_port_open`/`tty_port_close` (generic, đòi
  port->ops khác NULL — dùng `struct tty_port_operations{}` rỗng),
  write → đường ghi console. `tty_alloc_driver(REAL_RAW|DYNAMIC_DEV)`
  + `tty_register_device(driver,0,NULL)` — đúng recipe
  `register_lines` của line.c.
- **1 struct console** (name "tty", index 0, CON_PRINTBUFFER|CON_ANYTIME)
  — printk route qua đây (`printk: legacy console [tty0] enabled`
  trong log = hợp đồng); kernel tự thêm `console=tty0` vào cmdline
  (um_arch DEFAULT_COMMAND_LINE_CONSOLE).
- **Input = thread đọc stdin**: `boot-info v3` thêm `stdio_in`
  (append-only; launcher GetStdHandle(STD_INPUT_HANDLE)); reader
  thread block trong NtReadFile → `tty_insert_flip_string` +
  `tty_flip_buffer_push` — pattern `deliver_alarm()` (host thread
  gọi thẳng vào kernel context, không cần irq/epoll). EOF/stdin hỏng
  → thread park sau 1 dòng log (loud, không silent). Raw console
  input handle (interactive thật) là việc M4 — CI pipe stdin là FILE
  handle nên NtReadFile chạy sạch.
- **Pitfall §4.1 #13** (ghi console race): mọi write ch funnel qua
  `nt_console_write()` (util.c) với spinlock `__sync` CAS (lock
  cmpxchg cả ELF lẫn PE — không cần SRWLock trong D9 table).

Chữ ký tty_operations 6.18 (lỗi compile gặp phải): `.write = ssize_t
(tty, const u8 *, size_t)`, `.write_room = unsigned int (tty)`.

## D15 — uaccess OS_WINDOWS = walker qua VMA tree, không phải page-table (2026-09-29)

**M3.7.** Upstream `arch/um/kernel/skas/uaccess.c` dựng uaccess trên
page table của `current->mm`: trên UML, guest VA space CHÍNH là địa
chỉ kernel (guest page = trang kernel; `virt_to_pte` + `page_address`
+ memcpy). Trên NT mô hình đó không tồn tại: guest address space sống
trong stub process (per-VMA views của section — D10/M3), kernel chỉ
biết nó qua `uml_nt_mm` của conn. Vì vậy dưới `CONFIG_OS_WINDOWS`:

- Patch **0014** bỏ `uaccess.o` upstream khỏi `arch/um/kernel/skas/`
  (giữ cho OS_LINUX); `os-Windows/skas/uaccess.c` cung cấp cùng
  contract: `raw_copy_from_user/to_user`, `strncpy_from_user`,
  `strnlen_user`, `__clear_user` + 2 futex atomic.
- Phần walker là file PURE `uaccess_walk.c` (unit test Linux CI):
  dịch guest VA từng chunk 4K (chunk không bao giờ vường VMA biên —
  VMA là bội run 64K), memcpy/strnlen qua flat view
  `uml_boot.physmem_base + off`. All-or-nothing (-1 khi có byte
  không map được); convention retval theo upstream (raw_copy_* trả
  số byte CHƯA copy; strnlen_user trả 0 = fault).
- **Nguồn mm**: dispatch (D16) cài `uml_nt_uacc_set_mm(conn->mm)`
  cho ĐÚNG MỘT lượt chạy handler rồi trả NULL — ngoài handler mọi
  uaccess fault (fail-safe, không bao giờ deref mù qua flat view).
  VFS syscall thật của guest sẽ dùng cùng seam khi có task context
  (M3.8).
- Futex atomic = translate 4 byte + `__sync` trên flat view — đúng
  cho trang private; futex trên trang COW-shared sẽ ghi Shared page
  không fault (threads là M5, ghép cùng M4 signals).
- `__access_ok` giữ generic (guest VA < TASK_SIZE là đủ — translate
  mới là phán quyết cuối).

## D16 — Syscall surface = dispatch riêng trong os-Windows/skas/syscall.c (2026-09-29)

**M3.7.** Bề mặt syscall guest phục vụ theo conn (1 conn = 1 guest
process), shape giống `handle_syscall` upstream: `d->regs.rax` = nr,
`d->args[6]` = ABI (rdi rsi rdx r10 r8 r9), retval về `d->retval`.
Điểm dời Reality NT:

- **Ops kèm syscall**: mmap/munmap/mprotect trả kết quả bằng cách
  STREAM stub ops qua cơ chế plan sẵn có (stub tự thao tác address
  space của chính nó — đúng mô hình seccomp-stub upstream); retval
  syscall được PARK trong `conn->plan_retval` vì `d->retval` đang
  là kênh vận chuyển kết quả từng op (do_action ghi 1/0) — plan
  rỗng mới republish retval trước NONE cuối. Đây là lý do
  `plan_has_retval` tồn tại (INIT/FAULT đặt 0).
- **Thứ tự theo busybox /init**: exit/exit_group (halt), getpid/
  gettid/getppid/get*id, set_tid_address, rt_sigprocmask/rt_sigaction
  (no-op POC), brk (heap run đặt trước trong mm — buddy không nợ
  kề nhau nên heap KHÔNG vượt reservation; hết chỗ = ENOMEM), mmap
  anon|private (+MAP_FIXED trên vùng FREE; file-backed = ENOSYS),
  mprotect (1 VMA, không COW), munmap (trọn VMA — UnmapViewOfFile
  là whole-view), write (fd 0/1/2 = console), read (ENOSYS tới
  M3.8), ioctl → ENOTTY (non-interactive), wait4 (reap con ĐÃ
  chết; con sống → -EAGAIN — block thật cần scheduler M3.8),
  fork/clone(!CLONE_VM) → hook `uml_nt_sys_fork` (cỗ máy M3.3).
- **Mặc định = -ENOSYS + os_info loud** — chính là "mỗi boot fail
  chỉ syscall thiếu kế tiếp": log nêu nr để thêm handler tiếp.
- **KHÔNG mô phỏng openat/fstat/getdents64/execve** ở tầng này:
  bytes nằm trong ext4 trên ubda, chỉ VFS của guest đọc được —
  cần kernel task thật chạy userspace() loop (M3.8); mô phỏng
  tắt đường VFS = phá khoá kiến trúc M3.5.
