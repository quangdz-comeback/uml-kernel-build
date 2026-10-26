/* WHO TOUCHED THE CONTEXT? — Shelley 183.
 *
 * Every death of this hunt happens in the round we just answered, which
 * makes the ContextRecord itself the one suspect never measured: our GPR
 * and DR writes sit next to the XSAVE area inside the same record, and a
 * write that ran eight bytes long would land in the legacy XSAVE header.
 * The kernel's xrstor would then fault on content we made, the thread
 * dies with no user-mode handler — exactly the signature.
 *
 * This model answers one question about an offset inside CONTEXT: is a
 * change there something we MEANT to make? Everything else is evidence.
 * Pure logic, red-first in test_resume.c section 22.
 */
#ifndef _UML_NT_CTXAUDIT_MODEL_H
#define _UML_NT_CTXAUDIT_MODEL_H

enum uml_nt_ctxword {
	UML_NT_CTX_INTENDED = 0,	/* we write it on purpose */
	UML_NT_CTX_FOREIGN = 1,		/* nobody should have touched it */
};

/* The x64 CONTEXT layout we rely on (Windows ABI):
 *   0x30 ContextFlags   0x34 MxCsr      0x38 SegCs .. 0x44 EFlags
 *   0x48 Dr0 .. 0x78 Dr7
 *   0x78 Rax .. 0xf8 Rip
 *   then the legacy FP area and the XSAVE header follow inside the record.
 */
static inline int uml_nt_ctx_word_is_intended(unsigned long long off)
{
	if (off == 0x30 || off == 0x34)		/* ContextFlags, MxCsr */
		return 1;
	if (off >= 0x38 && off <= 0x44)		/* SegCs..SegGs, EFlags */
		return 1;
	if (off >= 0x48 && off <= 0x78)		/* Dr0..Dr7 (0x78 = Dr7) */
		return off <= 0x78;
	if (off >= 0x78 && off <= 0xf8)		/* Rax..Rip (shared 0x78) */
		return 1;
	return 0;
}

static inline const char *uml_nt_ctx_word_name(unsigned long long off)
{
	if (off == 0x30)
		return "ContextFlags";
	if (off == 0x34)
		return "MxCsr";
	if (off == 0x38)
		return "SegCs";
	if (off == 0x3c)
		return "SegDs";
	if (off == 0x40)
		return "SegEs";
	if (off == 0x44)
		return "SegFs/Eflags";
	if (off >= 0x48 && off <= 0x68)
		return "Dr0..Dr3";
	if (off == 0x6c)
		return "Dr6";
	if (off == 0x70 || off == 0x78)
		return "Dr7/Rax";
	return "GPR";
}

#endif
