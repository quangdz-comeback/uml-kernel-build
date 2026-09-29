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
  VMA) — thiết kế mở cho M4 (stack thật, ELF loader).
- Ràng buộc NT giữ nguyên (mm_clone): VMA giữ rsp phải eager-copy lúc
  fork — VEH dispatch đẩy exception frame lên stack bị fault, trang
  COW-RO giết dispatch trước khi handler chạy.
- Giả định identity `va == RAM_BASE + run_off` chỉ đúng cho run CHƯA
  bị COW-copy; syscall translate (write/…, M3.7) phải đi qua VMA tree
  (`va → vma → run_off + (va - start)`), không trừ thẳng ram_base.
