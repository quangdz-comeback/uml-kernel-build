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

## D17 — Guest exec qua binfmt_umlnt riêng (2026-09-29, Shelley duyệt chốt)

**Quyết định:** thêm binfmt handler riêng `binfmt_umlnt` (hướng a) cho execve
guest — KHÔNG patch binfmt_elf ép align 64K (hướng b, loại).

**Lý do:**
- binfmt_elf upstream giả định ptes/guest-VA = kernel-VA — không tồn tại trên
  backend này. Patch nó = mượn code nhưng đánh cắp semantics, churn rebase lớn.
- Module song song đúng triết lý D-series (os-Windows song song os-Linux,
  không fork core): backing guest VA = section views (D10/D11), uaccess đi
  VMA tree (D15), không ptes.
- Loader kernel-side M3.4 (skas/elf.c) tái sử dụng làm phần nạp của handler.

**Hệ quả (đã chốt trong audit M3.8):**
- `mm_id` thêm `void *nt_conn` (patch 0015, #ifdef OS_WINDOWS) — conn chứa
  state D10 (events/proc/mm/plan); init_new_context/destroy_context →
  uml_nt_mmctx_init/destroy (spawn/kill stub thật, bỏ park).
- userspace() per-task: interrupt_end → sync plan → set regs → wait evt_in
  (turnstile per-conn) → serve (syscall qua D16 handle_syscall, fault qua
  uml_nt_mm_fault, halt → kill+reap) → lặp. Probe M3.7 và boot dùng chung
  giao thức, hai đường.
- Hazard (3) COW write-back trong uaccess to_user còn mở — fix SAU S3,
  trước S4 (sketch đã có trong relay archive).

## D18 — FS base của guest thread: state per-conn + wrfsbase khi resume (2026-09-29, Shelley duyệt)

**Quyết định:** FS base là state per-conn lưu trong regs của stub_data.
`arch_prctl(ARCH_SET_FS)` (syscall 158) chỉ GHI giá trị vào regs — không NT
call nào. Stub apply bằng `wrfsbase` ngay trước khi resume guest (FSGSBASE
gate bằng CPUID — probe S4c đã xác nhận native runner có; CPU không hỗ trợ →
boot loud-fail, chấp nhận yêu cầu phần cứng hiện đại).

**Lý do:**
- x86_64 TLS (musl/glibc) dùng FS base, không phải SegFs 32-bit legacy —
  không có đường NT nào set FS base cho thread khác; wrfsbase là đường
  chuẩn và rẻ (một lệnh, không syscall).
- Parity upstream: ptrace-mode cũng chỉ GETREGS/SETREGS gp regs — FS base
  đi qua regs của stub data, kernel không cần biết chi tiết.
- VEH resume đã viết CONTEXT trước khi trả — wrfsbase trong stub ngay trước
  jump-back không bị VEH dispatch phá (RIP filter đã có từ S3).

**Phạm vi S4d (tách khỏi S4c2):** xmm/xstate fidelity cho FAULT path —
syscall boundary không cần FP (caller-saved ABI), nhưng SIGSEGV/sigreturn
cần fpstate. Giữ CONTEXT_FULL (XSAVE) trong VEH path, stub_data mở rộng
khối fp khi làm S4d.

## D19 — Mô hình concurrency NT: chỉ vCPU thread chạy kernel code (2026-09-29, Shelley duyệt)

**Quyết định:** các NT thread phụ trợ (timer/alarm, console reader, sau này
io/netstack) là **edge-capture only** — bắt sự kiện rồi handoff qua flag/handle;
TUYỆT ĐỐI không chạy kernel context. Toàn bộ kernel code (tick handler
do_IRQ→do_timer, softirq...) chạy trên vCPU thread tại điểm unblock
(block_signals/unblock_signals — đúng chỗ upstream SIGALRM được phép deliver).

**Bối cảnh (root cause S4c2 busybox crash):** upstream serialize tick bằng
OS signal mask — SIGALRM chỉ có thể fire trên vCPU thread khi unblock. Port
NT giữ nguyên flag machine nhưng chuyển delivery sang timer NT thread riêng →
tick (deliver_alarm → do_IRQ → do_timer → event_handler) chạy đồng thời với
vCPU đang mid-exec trong cửa sổ execve busybox → rác DETERMINISTIC
(physmem=0x400000001, high_physmem=0x62000200 — address-shaped, guest-window
flavored) đè 2 word .bss kề nhau; kmem_cache_free sau đó free con trỏ bình
thường qua virt_to_page với base đã rác. Fix `520e9a9`: timer thread chỉ set
pending — alarm chờ vCPU unblock (parity upstream semantics).

**Hệ quả:**
- Rule review cho mọi thread mới (M4 io thread, M5 netstack): không bao giờ
  gọi vào kernel từ thread phụ; handoff qua conn/flag, vCPU xử lý.
- Canary "os-I/O funnel" (5e98421+) giữ làm hạ tầng chẩn đoán thường trực —
  mọi write vào physmem qua os-I/O giờ có thể trace call-site.
- Bài học dịch semantic: flag machine上游 dịch nguyên văn KHÔNG đủ — phải dịch
  cả INVARIANT serialization của nó (ai được chạy cái gì trên thread nào).

## D20 — binfmt_umlnt hỗ trợ dynamic ELF (PT_INTERP + glibc) (2026-09-30, Shelley duyệt)

**Quyết định:** mở rộng binfmt_umlnt load dynamic-PIE theo staged cluster
(audit 037 đã định vị): (1) đọc PT_INTERP → load interpreter (ET_DYN) vào
conn như ELF thứ hai, entry = interp entry, auxv đủ bộ AT_PHDR/AT_PHENT/
AT_PHNUM/AT_BASE/AT_ENTRY/AT_RANDOM/AT_PAGESZ/AT_UID... (mở rộng pure-fn
argv/envp/auxv hiện có — S4a); (2) glibc startup cluster theo census strace
thật (execve/openat/read/pread64/fstat/close/mmap/mprotect/munmap/brk/
access/arch_prctl/set_tid_address/set_robust_list/prlimit64/rseq) — audit
từng cái với pointer guest thật; (3) systemd cluster (mount cgroup2/
devtmpfs/tmpfs, signalfd, epoll_*, pidfd, sendfile, recvmsg/sendmsg,
AF_UNIX dgram, sched_setaffinity).

**Điểm thiết kế quan trọng — patch syscall cho dynamic pages:** scan_patch
hiện chạy lúc load static image. Với dynamic, libc/ld.so vào physmem qua
guest mmap syscall (đường S4b/M4) — vì patch là CENTRAL trong physmem section
(D10) và mọi stub thấy cùng trang, hook scan vào: (a) mỗi exec-able mapping
được map vào conn lần đầu, (b) hoặc lazy tại fault exec đầu tiên của page.
Chọn (a) — deterministic, không phá VEH RIP filter.

**Lý do:** systemd + mọi binary distro đều dynamic; đây là cửa vào "giống
Linux real" (M5.4/5.5/5.6). Wine chỉ để audit shape — native (M5.5 PVE
image) là trọng tài.

**Non-goal:** không patch binfmt_elf upstream; không vDSO giai đoạn này
(clock_gettime đã kernel-side — RTT 26µs chấp nhận được cho boot; vDSO
mở ở M6 nếu cần perf).

## D21 (2026-10-01, Astra one-shot phân tích — Shelley phê)
ET_EXEC lớn tại low guest VA thật + span backing có giới hạn.
- Vấn đề: (a) ET_EXEC nhiều PT_LOAD chồng (python3.11: 4 segment merge
  [0x400000,0xad0000) = 109 runs) → D12 đòi buddy order > MAX_PAGE_ORDER
  → NOMEM; (b) elf.c:255-265 rebase +0x60000000 KHÔNG relocate absolute
  pointers — ET_EXEC với absolute refs (python) vẫn invalid dù alloc xong;
  (c) binfmt.c:373 convert NOMEM(-7) thành ENOEXEC(-8) — che gốc rễ.
- Quyết: hỗ trợ ET_EXEC tại guest VA thật (0x400000...) — decouple guest
  address khỏi section offset xuyên suốt loader/VMA/stub trap filter;
  bound từng span backing liên tục (không đòi order > MAX_PAGE_ORDER —
  tách span, giữ copy/patch/protect/refcount xuyên span).
- CẤM: chỉ tăng MAX_PAGE_ORDER (không đủ, nguy hiểm); rebase + hi vọng
  relocate (sai với arbitrary ET_EXEC).
- Test-image rule: mask cloud-init units trên bản CI copy (provisioning
  fluff, không cần cho gate multi-user) — không phải fix kernel, chỉ
  tránh phụ thuộc python trước khi D21 land. D21 vẫn bắt buộc cho distro
  software thật (node/qemu/...).

## D22 (2026-10-01 khuya, Shelley phê — từ evidence 069/077/078/081)
Run lifecycle invariant: owner-view refcount + recycle-zero.
- Bệnh (bằng chứng hai chiều): free-while-mapped ×14+/boot + double-free
  0x3990000 + zero-read-back + chuỗi guest (STREAM=7 / a%UTEMD_S$UTEMD_ /
  EXEC_PID) landed trong malloc meta → run bị phys-free TRONG KHI view/
  mapping khác còn trỏ → trang tái cấp cho chuỗi/env, heap cũ đọc giá trị mới.
  Dice: trúng meta PID1 → abort (ĐỎ); chỉ trúng con → XANH (giải thích flake).
- Quyết: run chỉ phys-free khi (a) mọi view/VMA sở hữu đã unref, (b) mọi
  pending COW/plan op trên run đã settle. Trang tái cấp từ phys allocator
  PHẢI zero (recycle-zero) trước khi nhận mapping mới — không tin nội dung cũ.
- Ảnh hưởng: D12 phys backend ledger + conn view refs + fork handoff
  (arm/disarm/seed window 01dfd94 đã map) + private-block ledger (f2eb9c7).
- Trọng tài: unit test multi-owner run (2 view + fork giữa chừng + drop thứ
  tự sai phải không-free) + M5.5a gate vẫn xanh (dice phải mất).

## D24 (draft — hàng đợi sau D23, user nhắc từ patches/uml-memdrop-on-free.patch)
Memdrop analog: run phys unref-to-0 + settle → MEM_DECOMMIT trong flat view
(trả RAM host; re-commit = trang zero tươi → D22 recycle-zero miễn phí).
Điều kiện: chỉ run refs==0 đã settle. Mục tiêu: guest lớn/LXC không giữ
high-water mark. Kế thừa: patches/uml-memdrop-on-free.patch (PAGE_REPORTING
+ MADV_REMOVE, thời Termux).
