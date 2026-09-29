# uml-nt M0 spikes (see ARCHITECTURE/PLAN in uml-msys2-research)

| Spike | File | Trả lời |
|---|---|---|
| S1 | `s1_veh.c` | VEH + EXCEPTION_CONTINUE_EXECUTION: CONTEXT sửa được (Rax/RIP+2), RIP redirect, PF addr via ExceptionInformation[1], callee-saved survivial; ns/trap ud2 + page fault |
| S2 | `s2_xproc.c` | RT event / parent-spin / both-spin trên section+inherited events; WaitOnAddress cross-proc (kỳ vọng không wake); Interlocked coherence |
| S3+S4 | `s3_launcher.c` + `s4_payload.c` | Nạp ELF ET_EXEC freestanding vào PE process, chạy entry, handshake qua fixed-VA window |
| S5 | `s5_spawn.c` | CreateProcess suspended/full latency; DiscardVirtualMemory private + section view; fixed-base MapViewOfFileEx 2 process |
| S6 | `s6_scan.c` | Đếm false-positive của naive `0F 05` scan vs linear-decoder vs objdump ground truth |

Build (MSYS2 MINGW64): `make -C uml-nt/spikes all` — CI: `.github/workflows/uml-nt-m0.yml`.
Kết quả local (Linux, S6): busybox static → naive 15 FP/302, decoder 302/302 0FP;
guest libc.so.6 → naive 10 FP/565, decoder 0 FP, 2 missed.
