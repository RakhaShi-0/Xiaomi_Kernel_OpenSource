// SPDX-License-Identifier: GPL-2.0
/*
 * Stub untuk __cfi_slowpath dan __cfi_slowpath_diag.
 * Dipakai supaya module vendor closed-source (dicompile dengan
 * CFI enabled) tetap bisa di-load di kernel yang CFI-nya dimatikan
 * (CONFIG_CFI_CLANG=n). Fungsi ini sengaja no-op: tidak melakukan
 * pengecekan control-flow integrity apapun, cuma menyediakan symbol
 * supaya linker/module loader tidak menolak module karena undefined
 * reference.
 */
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/types.h>

void __cfi_slowpath(uint64_t id, void *ptr)
{
	/* No-op: CFI check dilewati sepenuhnya */
}
EXPORT_SYMBOL(__cfi_slowpath);

void __cfi_slowpath_diag(uint64_t id, void *ptr, void *diag)
{
	/* No-op: CFI check dilewati sepenuhnya */
}
EXPORT_SYMBOL(__cfi_slowpath_diag);
