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
