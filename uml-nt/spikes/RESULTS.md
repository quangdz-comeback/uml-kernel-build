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
