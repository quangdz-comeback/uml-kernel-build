/* SPDX-License-Identifier: GPL-2.0 */
/*
 * console-status classifier (pure — unit-tested on the host CI):
 * the NT statuses a console NtReadFile can return with zero
 * iosb.Information. RETRY = a spurious wake/wait — re-arm the read;
 * FATAL = the stdin is really gone (closed/EOF/handle death).
 */
#ifndef __UML_NT_CONSOLE_STATUS_H
#define __UML_NT_CONSOLE_STATUS_H

#define NT_CON_RETRY 0
#define NT_CON_FATAL 1

int nt_con_status_class(long long status);

#endif /* __UML_NT_CONSOLE_STATUS_H */
