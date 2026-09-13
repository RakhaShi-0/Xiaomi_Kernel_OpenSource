// SPDX-License-Identifier: GPL-2.0
/*
 * STUB PAKSA untuk symbol WMT/connsys yang tidak tersedia di kernel
 * custom ini. Fungsi-fungsi ini seharusnya diimplementasikan oleh
 * wmt_drv.ko/connfem.ko asli, tapi karena symbol export tidak
 * ter-resolve dengan benar, kita sediakan versi stub supaya module
 * lain (wmt_chrdev_wifi, wlan_drv_gen4m, bt_drv_connac1x) bisa
 * di-load tanpa error "Unknown symbol".
 *
 * PERINGATAN: Fungsi-fungsi ini TIDAK melakukan apapun secara nyata.
 * WiFi/Bluetooth kemungkinan besar TIDAK akan benar-benar berfungsi
 * meski module berhasil di-load, karena logic aslinya kosong.
 * Gunakan hanya untuk keperluan testing/debug.
 */
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/types.h>

int mtk_wcn_wmt_func_on(void *drv)
{
	return 0;
}
EXPORT_SYMBOL(mtk_wcn_wmt_func_on);

int mtk_wcn_wmt_func_off(void *drv)
{
	return 0;
}
EXPORT_SYMBOL(mtk_wcn_wmt_func_off);

int mtk_wcn_wmt_msgcb_reg(int drv, void *cb)
{
	return 0;
}
EXPORT_SYMBOL(mtk_wcn_wmt_msgcb_reg);

int mtk_wcn_wmt_msgcb_unreg(int drv)
{
	return 0;
}
EXPORT_SYMBOL(mtk_wcn_wmt_msgcb_unreg);

int mtk_wcn_wmt_wlan_reg(void *cb)
{
	return 0;
}
EXPORT_SYMBOL(mtk_wcn_wmt_wlan_reg);

int mtk_wcn_wmt_wlan_unreg(void)
{
	return 0;
}
EXPORT_SYMBOL(mtk_wcn_wmt_wlan_unreg);

int mtk_wcn_wmt_do_reset_only(void)
{
	return 0;
}
EXPORT_SYMBOL(mtk_wcn_wmt_do_reset_only);

int mtk_wcn_wmt_assert(int drv, int type)
{
	return 0;
}
EXPORT_SYMBOL(mtk_wcn_wmt_assert);

int mtk_wcn_wmt_assert_keyword(int drv, char *kw, int len)
{
	return 0;
}
EXPORT_SYMBOL(mtk_wcn_wmt_assert_keyword);

int mtk_wcn_wmt_psm_ctrl(int type)
{
	return 0;
}
EXPORT_SYMBOL(mtk_wcn_wmt_psm_ctrl);

int mtk_wcn_wmt_ic_info_get(void *info)
{
	return 0;
}
EXPORT_SYMBOL(mtk_wcn_wmt_ic_info_get);

int mtk_wcn_wmt_adie_workable(void)
{
	return 0;
}
EXPORT_SYMBOL(mtk_wcn_wmt_adie_workable);

void mtk_wcn_set_connsys_power_off_flag(int flag)
{
}
EXPORT_SYMBOL(mtk_wcn_set_connsys_power_off_flag);

int mtk_wcn_consys_hw_wifi_paldo_ctrl(int on)
{
	return 0;
}
EXPORT_SYMBOL(mtk_wcn_consys_hw_wifi_paldo_ctrl);

void wifi_reset_start(void)
{
}
EXPORT_SYMBOL(wifi_reset_start);

void wifi_reset_end(void)
{
}
EXPORT_SYMBOL(wifi_reset_end);

int mtk_wcn_stp_set_bluez(int en)
{
	return 0;
}
EXPORT_SYMBOL(mtk_wcn_stp_set_bluez);

int mtk_wcn_stp_register_event_cb(int type, void *cb)
{
	return 0;
}
EXPORT_SYMBOL(mtk_wcn_stp_register_event_cb);

int mtk_wcn_stp_is_rxqueue_empty(void)
{
	return 1;
}
EXPORT_SYMBOL(mtk_wcn_stp_is_rxqueue_empty);

int mtk_wcn_stp_receive_data(unsigned char *buf, unsigned int len, int type)
{
	return 0;
}
EXPORT_SYMBOL(mtk_wcn_stp_receive_data);

int mtk_wcn_stp_send_data(unsigned char *buf, unsigned int len, int type)
{
	return 0;
}
EXPORT_SYMBOL(mtk_wcn_stp_send_data);

int mtk_wcn_stp_is_ready(void)
{
	return 0;
}
EXPORT_SYMBOL(mtk_wcn_stp_is_ready);

int connsys_log_init(void)
{
	return 0;
}
EXPORT_SYMBOL(connsys_log_init);

void connsys_log_deinit(void)
{
}
EXPORT_SYMBOL(connsys_log_deinit);

int connsys_log_register_event_cb(void *cb)
{
	return 0;
}
EXPORT_SYMBOL(connsys_log_register_event_cb);

int connsys_log_read_to_user(char __user *buf, int len)
{
	return 0;
}
EXPORT_SYMBOL(connsys_log_read_to_user);

int connsys_log_get_buf_size(void)
{
	return 0;
}
EXPORT_SYMBOL(connsys_log_get_buf_size);
