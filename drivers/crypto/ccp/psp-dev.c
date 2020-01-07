/*
 * AMD Platform Security Processor (PSP) interface
 *
 * Copyright (C) 2016,2018 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/hw_random.h>
#include <linux/ccp.h>
#include <linux/firmware.h>

#include <asm/amd_nb.h>

#define IN_LINUX
#include <linux/psp-stub.h>

#include "sp-dev.h"
#include "psp-dev.h"

#define SEV_VERSION_GREATER_OR_EQUAL(_maj, _min)	\
		((psp_master->api_major) >= _maj &&	\
		 (psp_master->api_minor) >= _min)

#define DEVICE_NAME		"sev"
#define SEV_FW_FILE		"amd/sev.fw"
#define SEV_FW_NAME_SIZE	64

static DEFINE_MUTEX(sev_cmd_mutex);
static struct sev_misc_dev *misc_dev;
static struct psp_device *psp_master;

static int psp_cmd_timeout = 100;
module_param(psp_cmd_timeout, int, 0644);
MODULE_PARM_DESC(psp_cmd_timeout, " default timeout value, in seconds, for PSP commands");

static int psp_probe_timeout = 5;
module_param(psp_probe_timeout, int, 0644);
MODULE_PARM_DESC(psp_probe_timeout, " default timeout value, in seconds, during PSP device probe");

static int psp_emu_enabled = 0;
module_param(psp_emu_enabled, int, 0644);
MODULE_PARM_DESC(psp_emu_enabled, " flag whether the emulated PSP should be used (requires the PSP emulator running with SEV app in userspace)");

static bool psp_dead;
static int psp_timeout;

/* Trusted Memory Region (TMR):
 *   The TMR is a 1MB area that must be 1MB aligned.  To accomplish this
 *   allocate an amount that is the size of area and the required alignment.
 *   The aligned address will be calculated from the returned address.
 */
#define SEV_ES_TMR_ALIGN	(1024 * 1024)
#define SEV_ES_TMR_SIZE		(1024 * 1024)
#define SEV_ES_TMR_LEN		(SEV_ES_TMR_ALIGN + SEV_ES_TMR_SIZE)
static void *sev_es_tmr;

static struct psp_device *psp_alloc_struct(struct sp_device *sp)
{
	struct device *dev = sp->dev;
	struct psp_device *psp;

	psp = devm_kzalloc(dev, sizeof(*psp), GFP_KERNEL);
	if (!psp)
		return NULL;

	psp->dev = dev;
	psp->sp = sp;

	snprintf(psp->name, sizeof(psp->name), "psp-%u", sp->ord);

	return psp;
}

static irqreturn_t psp_irq_handler(int irq, void *data)
{
	struct psp_device *psp = data;
	unsigned int status;
	int reg;

	/* Read the interrupt status: */
	status = ioread32(psp->io_regs + psp->vdata->intsts_reg);

	/* Check if it is command completion: */
	if (!(status & PSP_CMD_COMPLETE))
		goto done;

	/* Check if it is SEV command completion: */
	reg = ioread32(psp->io_regs + psp->vdata->cmdresp_reg);
	if (reg & PSP_CMDRESP_RESP) {
		psp->sev_int_rcvd = 1;
		wake_up(&psp->sev_int_queue);
	}

done:
	/* Clear the interrupt status by writing the same value we read. */
	iowrite32(status, psp->io_regs + psp->vdata->intsts_reg);

	return IRQ_HANDLED;
}

static int sev_wait_cmd_ioc(struct psp_device *psp,
			    unsigned int *reg, unsigned int timeout)
{
	int ret;

	ret = wait_event_timeout(psp->sev_int_queue,
			psp->sev_int_rcvd, timeout * HZ);
	if (!ret)
		return -ETIMEDOUT;

	*reg = ioread32(psp->io_regs + psp->vdata->cmdresp_reg);

	return 0;
}

static int sev_cmd_buffer_len(int cmd)
{
	switch (cmd) {
	case SEV_CMD_INIT:			return sizeof(struct sev_data_init);
	case SEV_CMD_PLATFORM_STATUS:		return sizeof(struct sev_user_data_status);
	case SEV_CMD_PEK_CSR:			return sizeof(struct sev_data_pek_csr);
	case SEV_CMD_PEK_CERT_IMPORT:		return sizeof(struct sev_data_pek_cert_import);
	case SEV_CMD_PDH_CERT_EXPORT:		return sizeof(struct sev_data_pdh_cert_export);
	case SEV_CMD_LAUNCH_START:		return sizeof(struct sev_data_launch_start);
	case SEV_CMD_LAUNCH_UPDATE_DATA:	return sizeof(struct sev_data_launch_update_data);
	case SEV_CMD_LAUNCH_UPDATE_VMSA:	return sizeof(struct sev_data_launch_update_vmsa);
	case SEV_CMD_LAUNCH_FINISH:		return sizeof(struct sev_data_launch_finish);
	case SEV_CMD_LAUNCH_MEASURE:		return sizeof(struct sev_data_launch_measure);
	case SEV_CMD_ACTIVATE:			return sizeof(struct sev_data_activate);
	case SEV_CMD_DEACTIVATE:		return sizeof(struct sev_data_deactivate);
	case SEV_CMD_DECOMMISSION:		return sizeof(struct sev_data_decommission);
	case SEV_CMD_GUEST_STATUS:		return sizeof(struct sev_data_guest_status);
	case SEV_CMD_DBG_DECRYPT:		return sizeof(struct sev_data_dbg);
	case SEV_CMD_DBG_ENCRYPT:		return sizeof(struct sev_data_dbg);
	case SEV_CMD_SEND_START:		return sizeof(struct sev_data_send_start);
	case SEV_CMD_SEND_UPDATE_DATA:		return sizeof(struct sev_data_send_update_data);
	case SEV_CMD_SEND_UPDATE_VMSA:		return sizeof(struct sev_data_send_update_vmsa);
	case SEV_CMD_SEND_FINISH:		return sizeof(struct sev_data_send_finish);
	case SEV_CMD_RECEIVE_START:		return sizeof(struct sev_data_receive_start);
	case SEV_CMD_RECEIVE_FINISH:		return sizeof(struct sev_data_receive_finish);
	case SEV_CMD_RECEIVE_UPDATE_DATA:	return sizeof(struct sev_data_receive_update_data);
	case SEV_CMD_RECEIVE_UPDATE_VMSA:	return sizeof(struct sev_data_receive_update_vmsa);
	case SEV_CMD_LAUNCH_UPDATE_SECRET:	return sizeof(struct sev_data_launch_secret);
	case SEV_CMD_DOWNLOAD_FIRMWARE:		return sizeof(struct sev_data_download_firmware);
	case SEV_CMD_GET_ID:			return sizeof(struct sev_data_get_id);
	case PSP_STUB_LOAD_BIN:			return sizeof(PSPSTUBREQLOADBIN);
	case PSP_STUB_EXEC_BIN:			return sizeof(PSPSTUBREQEXECBIN);
	case PSP_STUB_SMN_READ:			return sizeof(PSPSTUBREQSMNRW);
	case PSP_STUB_SMN_WRITE:			return sizeof(PSPSTUBREQSMNRW);
	case PSP_STUB_PSP_READ:			return sizeof(PSPSTUBREQPSPRW);
	case PSP_STUB_PSP_WRITE:			return sizeof(PSPSTUBREQPSPRW);
	case PSP_STUB_CALL_SVC:			return sizeof(PSPSTUBREQCALLSVC);
	case PSP_STUB_QUERY_INFO:			return sizeof(PSPSTUBREQQUERYINFO);
	default:				return 0;
	}

	return 0;
}

static int __sev_emu_do_cmd_locked(struct psp_device *psp, int cmd, unsigned int phys_lsb, unsigned int phys_msb, int *psp_ret)
{
	int ret = 0;

	while (atomic_read(&psp->sev_emu_wait_for_wrk) == 0)
	{
		ret = schedule_timeout_interruptible(msecs_to_jiffies(psp_cmd_timeout * 1000));
		if (!ret)
			return -ETIMEDOUT;
	}

	psp->cmd	  = cmd;
	psp->phys_lsb = phys_lsb;
	psp->phys_msb = phys_msb;
	psp->ret      = 0;

	psp->sev_emu_wrk_done  = 0;
	psp->sev_emu_wrk_ready = 1;
	wake_up(&psp->sev_emu_wrk_ready_queue);

	ret = wait_event_interruptible_timeout(psp->sev_emu_wrk_done_queue, psp->sev_emu_wrk_done, msecs_to_jiffies(psp_cmd_timeout * 1000));
	if (ret == -ERESTARTSYS)
		return ret;
	if (!ret)
		return -ETIMEDOUT;

	*psp_ret = psp->ret;
	return 0;
}

static int __sev_do_cmd_locked(int cmd, void *data, int *psp_ret)
{
	struct psp_device *psp = psp_master;
	unsigned int phys_lsb, phys_msb;
	unsigned int reg, ret = 0;

	if (!psp)
		return -ENODEV;

	if (psp_dead)
		return -EBUSY;

	/* Get the physical address of the command buffer */
	phys_lsb = data ? lower_32_bits(__psp_pa(data)) : 0;
	phys_msb = data ? upper_32_bits(__psp_pa(data)) : 0;

	dev_dbg(psp->dev, "sev command id %#x buffer 0x%08x%08x timeout %us\n",
		cmd, phys_msb, phys_lsb, psp_timeout);

	print_hex_dump_debug("(in):  ", DUMP_PREFIX_OFFSET, 16, 2, data,
			     sev_cmd_buffer_len(cmd), false);

	if (   psp_emu_enabled
		&& psp->emu_available
		&& cmd < PSP_STUB_REQ_FIRST)
		return __sev_emu_do_cmd_locked(psp_master, cmd, phys_lsb, phys_msb, psp_ret);

	iowrite32(phys_lsb, psp->io_regs + psp->vdata->cmdbuff_addr_lo_reg);
	iowrite32(phys_msb, psp->io_regs + psp->vdata->cmdbuff_addr_hi_reg);

	psp->sev_int_rcvd = 0;

	reg = cmd;
	reg <<= PSP_CMDRESP_CMD_SHIFT;
	reg |= PSP_CMDRESP_IOC;
	iowrite32(reg, psp->io_regs + psp->vdata->cmdresp_reg);

	/* wait for command completion */
	ret = sev_wait_cmd_ioc(psp, &reg, psp_timeout);
	if (ret) {
		if (psp_ret)
			*psp_ret = 0;

		dev_err(psp->dev, "sev command %#x timed out, disabling PSP \n", cmd);
		psp_dead = true;

		return ret;
	}

	psp_timeout = psp_cmd_timeout;

	if (psp_ret)
		*psp_ret = reg & PSP_CMDRESP_ERR_MASK;

	if (reg & PSP_CMDRESP_ERR_MASK) {
		dev_dbg(psp->dev, "sev command %#x failed (%#010x)\n",
			cmd, reg & PSP_CMDRESP_ERR_MASK);
		ret = -EIO;
	}

	print_hex_dump_debug("(out): ", DUMP_PREFIX_OFFSET, 16, 2, data,
			     sev_cmd_buffer_len(cmd), false);

	return ret;
}

static int sev_do_cmd(int cmd, void *data, int *psp_ret)
{
	int rc;

	//mutex_lock(&sev_cmd_mutex);
	rc = __sev_do_cmd_locked(cmd, data, psp_ret);
	//mutex_unlock(&sev_cmd_mutex);

	return rc;
}

static int __sev_platform_init_locked(int *error)
{
	struct psp_device *psp = psp_master;
	int rc = 0;

	if (!psp)
		return -ENODEV;

	if (psp->sev_state == SEV_STATE_INIT)
		return 0;

	if (sev_es_tmr) {
		u64 tmr_pa;

		/*
		 * Do not include the encryption mask on the physical
		 * address of the TMR (firmware should clear it anyway).
		 */
		tmr_pa = __pa(sev_es_tmr);
		tmr_pa = ALIGN(tmr_pa, SEV_ES_TMR_ALIGN);

		psp->init_cmd_buf.flags |= 1/*SEV_INIT_FLAGS_SEV_ES*/;
		psp->init_cmd_buf.tmr_address = tmr_pa;
		psp->init_cmd_buf.tmr_len = SEV_ES_TMR_SIZE;
	}
	rc = __sev_do_cmd_locked(SEV_CMD_INIT, &psp->init_cmd_buf, error);
	if (rc)
		return rc;

	rc = __sev_do_cmd_locked(PSP_STUB_QUERY_INFO, &psp->query_info_cmd_buf, error);
	if (rc)
		dev_info(psp->dev, "Failed to query BinLoader info rc=%d\n", rc);
	else
		dev_info(psp->dev, "Queried BinLoader information: PspScratchAddr=%#x cbScratch=%#x\n",
			 psp->query_info_cmd_buf.u32PspScratchAddr, psp->query_info_cmd_buf.cbScratch);

	if (psp_emu_enabled)
		psp->sev_state = SEV_STATE_UNINIT;
	else
		psp->sev_state = SEV_STATE_INIT;
	dev_dbg(psp->dev, "SEV firmware initialized\n");

	return rc;
}

int sev_platform_init(int *error)
{
	int rc;

	mutex_lock(&sev_cmd_mutex);
	rc = __sev_platform_init_locked(error);
	mutex_unlock(&sev_cmd_mutex);

	return rc;
}
EXPORT_SYMBOL_GPL(sev_platform_init);

static int __sev_platform_shutdown_locked(int *error)
{
	int ret;

	ret = __sev_do_cmd_locked(SEV_CMD_SHUTDOWN, NULL, error);
	if (ret)
		return ret;

	psp_master->sev_state = SEV_STATE_UNINIT;
	dev_dbg(psp_master->dev, "SEV firmware shutdown\n");

	return ret;
}

static int sev_platform_shutdown(int *error)
{
	int rc;

	mutex_lock(&sev_cmd_mutex);
	rc = __sev_platform_shutdown_locked(NULL);
	mutex_unlock(&sev_cmd_mutex);

	return rc;
}

static int sev_get_platform_state(int *state, int *error)
{
	int rc;

	rc = __sev_do_cmd_locked(SEV_CMD_PLATFORM_STATUS,
				 &psp_master->status_cmd_buf, error);
	if (rc)
		return rc;

	*state = psp_master->status_cmd_buf.state;
	return rc;
}

static int sev_ioctl_do_reset(struct sev_issue_cmd *argp)
{
	int state, rc;

	/*
	 * The SEV spec requires that FACTORY_RESET must be issued in
	 * UNINIT state. Before we go further lets check if any guest is
	 * active.
	 *
	 * If FW is in WORKING state then deny the request otherwise issue
	 * SHUTDOWN command do INIT -> UNINIT before issuing the FACTORY_RESET.
	 *
	 */
	rc = sev_get_platform_state(&state, &argp->error);
	if (rc)
		return rc;

	if (state == SEV_STATE_WORKING)
		return -EBUSY;

	if (state == SEV_STATE_INIT) {
		rc = __sev_platform_shutdown_locked(&argp->error);
		if (rc)
			return rc;
	}

	return __sev_do_cmd_locked(SEV_CMD_FACTORY_RESET, NULL, &argp->error);
}

static int sev_ioctl_do_platform_status(struct sev_issue_cmd *argp)
{
	struct sev_user_data_status *data = &psp_master->status_cmd_buf;
	int ret;

	ret = __sev_do_cmd_locked(SEV_CMD_PLATFORM_STATUS, data, &argp->error);
	if (ret)
		return ret;

	if (copy_to_user((void __user *)argp->data, data, sizeof(*data)))
		ret = -EFAULT;

	return ret;
}

static int sev_ioctl_do_pek_pdh_gen(int cmd, struct sev_issue_cmd *argp)
{
	int rc;

	if (psp_master->sev_state == SEV_STATE_UNINIT) {
		rc = __sev_platform_init_locked(&argp->error);
		if (rc)
			return rc;
	}

	return __sev_do_cmd_locked(cmd, NULL, &argp->error);
}

static int sev_ioctl_do_pek_csr(struct sev_issue_cmd *argp)
{
	struct sev_user_data_pek_csr input;
	struct sev_data_pek_csr *data;
	void *blob = NULL;
	int ret;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	/* userspace wants to query CSR length */
	if (!input.address || !input.length)
		goto cmd;

	/* allocate a physically contiguous buffer to store the CSR blob */
	if (!access_ok(input.address, input.length) ||
	    input.length > SEV_FW_BLOB_MAX_SIZE) {
		ret = -EFAULT;
		goto e_free;
	}

	blob = kmalloc(input.length, GFP_KERNEL);
	if (!blob) {
		ret = -ENOMEM;
		goto e_free;
	}

	data->address = __psp_pa(blob);
	data->len = input.length;

cmd:
	if (psp_master->sev_state == SEV_STATE_UNINIT) {
		ret = __sev_platform_init_locked(&argp->error);
		if (ret)
			goto e_free_blob;
	}

	ret = __sev_do_cmd_locked(SEV_CMD_PEK_CSR, data, &argp->error);

	 /* If we query the CSR length, FW responded with expected data. */
	input.length = data->len;

	if (copy_to_user((void __user *)argp->data, &input, sizeof(input))) {
		ret = -EFAULT;
		goto e_free_blob;
	}

	if (blob) {
		if (copy_to_user((void __user *)input.address, blob, input.length))
			ret = -EFAULT;
	}

e_free_blob:
	kfree(blob);
e_free:
	kfree(data);
	return ret;
}

void *psp_copy_user_blob(u64 __user uaddr, u32 len)
{
	if (!uaddr || !len)
		return ERR_PTR(-EINVAL);

	/* verify that blob length does not exceed our limit */
	if (len > SEV_FW_BLOB_MAX_SIZE)
		return ERR_PTR(-EINVAL);

	return memdup_user((void __user *)(uintptr_t)uaddr, len);
}
EXPORT_SYMBOL_GPL(psp_copy_user_blob);

static int sev_get_api_version(void)
{
	struct sev_user_data_status *status;
	int error = 0, ret;

	status = &psp_master->status_cmd_buf;
	ret = sev_platform_status(status, &error);
	if (ret) {
		dev_err(psp_master->dev,
			"SEV: failed to get status. Error: %#x\n", error);
		return 1;
	}

	psp_master->api_major = status->api_major;
	psp_master->api_minor = status->api_minor;
	psp_master->build = status->build;
	psp_master->sev_state = status->state;

	return 0;
}

static int sev_get_firmware(struct device *dev,
			    const struct firmware **firmware)
{
	char fw_name_specific[SEV_FW_NAME_SIZE];
	char fw_name_subset[SEV_FW_NAME_SIZE];

	snprintf(fw_name_specific, sizeof(fw_name_specific),
		 "amd/amd_sev_fam%.2xh_model%.2xh.sbin",
		 boot_cpu_data.x86, boot_cpu_data.x86_model);

	snprintf(fw_name_subset, sizeof(fw_name_subset),
		 "amd/amd_sev_fam%.2xh_model%.1xxh.sbin",
		 boot_cpu_data.x86, (boot_cpu_data.x86_model & 0xf0) >> 4);

	/* Check for SEV FW for a particular model.
	 * Ex. amd_sev_fam17h_model00h.sbin for Family 17h Model 00h
	 *
	 * or
	 *
	 * Check for SEV FW common to a subset of models.
	 * Ex. amd_sev_fam17h_model0xh.sbin for
	 *     Family 17h Model 00h -- Family 17h Model 0Fh
	 *
	 * or
	 *
	 * Fall-back to using generic name: sev.fw
	 */
	if ((firmware_request_nowarn(firmware, fw_name_specific, dev) >= 0) ||
	    (firmware_request_nowarn(firmware, fw_name_subset, dev) >= 0) ||
	    (firmware_request_nowarn(firmware, SEV_FW_FILE, dev) >= 0))
		return 0;

	return -ENOENT;
}

/* Don't fail if SEV FW couldn't be updated. Continue with existing SEV FW */
static int sev_update_firmware(struct device *dev)
{
	struct sev_data_download_firmware *data;
	const struct firmware *firmware;
	int ret, error, order;
	struct page *p;
	u64 data_size;

	if (sev_get_firmware(dev, &firmware) == -ENOENT) {
		dev_dbg(dev, "No SEV firmware file present\n");
		return -1;
	}

	/*
	 * SEV FW expects the physical address given to it to be 32
	 * byte aligned. Memory allocated has structure placed at the
	 * beginning followed by the firmware being passed to the SEV
	 * FW. Allocate enough memory for data structure + alignment
	 * padding + SEV FW.
	 */
	data_size = ALIGN(sizeof(struct sev_data_download_firmware), 32);

	order = get_order(firmware->size + data_size);
	p = alloc_pages(GFP_KERNEL, order);
	if (!p) {
		ret = -1;
		goto fw_err;
	}

	/*
	 * Copy firmware data to a kernel allocated contiguous
	 * memory region.
	 */
	data = page_address(p);
	memcpy(page_address(p) + data_size, firmware->data, firmware->size);

	data->address = __psp_pa(page_address(p) + data_size);
	data->len = firmware->size;

	ret = sev_do_cmd(SEV_CMD_DOWNLOAD_FIRMWARE, data, &error);
	if (ret)
		dev_dbg(dev, "Failed to update SEV firmware: %#x\n", error);
	else
		dev_info(dev, "SEV firmware update successful\n");

	__free_pages(p, order);

fw_err:
	release_firmware(firmware);

	return ret;
}

static int sev_ioctl_do_pek_import(struct sev_issue_cmd *argp)
{
	struct sev_user_data_pek_cert_import input;
	struct sev_data_pek_cert_import *data;
	void *pek_blob, *oca_blob;
	int ret;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	/* copy PEK certificate blobs from userspace */
	pek_blob = psp_copy_user_blob(input.pek_cert_address, input.pek_cert_len);
	if (IS_ERR(pek_blob)) {
		ret = PTR_ERR(pek_blob);
		goto e_free;
	}

	data->pek_cert_address = __psp_pa(pek_blob);
	data->pek_cert_len = input.pek_cert_len;

	/* copy PEK certificate blobs from userspace */
	oca_blob = psp_copy_user_blob(input.oca_cert_address, input.oca_cert_len);
	if (IS_ERR(oca_blob)) {
		ret = PTR_ERR(oca_blob);
		goto e_free_pek;
	}

	data->oca_cert_address = __psp_pa(oca_blob);
	data->oca_cert_len = input.oca_cert_len;

	/* If platform is not in INIT state then transition it to INIT */
	if (psp_master->sev_state != SEV_STATE_INIT) {
		ret = __sev_platform_init_locked(&argp->error);
		if (ret)
			goto e_free_oca;
	}

	ret = __sev_do_cmd_locked(SEV_CMD_PEK_CERT_IMPORT, data, &argp->error);

e_free_oca:
	kfree(oca_blob);
e_free_pek:
	kfree(pek_blob);
e_free:
	kfree(data);
	return ret;
}

static int sev_ioctl_do_get_id(struct sev_issue_cmd *argp)
{
	struct sev_data_get_id *data;
	u64 data_size, user_size;
	void *id_blob, *mem;
	int ret;

	/* SEV GET_ID available from SEV API v0.16 and up */
	if (!SEV_VERSION_GREATER_OR_EQUAL(0, 16))
		return -ENOTSUPP;

	/* SEV FW expects the buffer it fills with the ID to be
	 * 8-byte aligned. Memory allocated should be enough to
	 * hold data structure + alignment padding + memory
	 * where SEV FW writes the ID.
	 */
	data_size = ALIGN(sizeof(struct sev_data_get_id), 8);
	user_size = sizeof(struct sev_user_data_get_id);

	mem = kzalloc(data_size + user_size, GFP_KERNEL);
	if (!mem)
		return -ENOMEM;

	data = mem;
	id_blob = mem + data_size;

	data->address = __psp_pa(id_blob);
	data->len = user_size;

	ret = __sev_do_cmd_locked(SEV_CMD_GET_ID, data, &argp->error);
	if (!ret) {
		if (copy_to_user((void __user *)argp->data, id_blob, data->len))
			ret = -EFAULT;
	}

	kfree(mem);

	return ret;
}

static int sev_ioctl_do_pdh_export(struct sev_issue_cmd *argp)
{
	struct sev_user_data_pdh_cert_export input;
	void *pdh_blob = NULL, *cert_blob = NULL;
	struct sev_data_pdh_cert_export *data;
	int ret;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	/* Userspace wants to query the certificate length. */
	if (!input.pdh_cert_address ||
	    !input.pdh_cert_len ||
	    !input.cert_chain_address)
		goto cmd;

	/* Allocate a physically contiguous buffer to store the PDH blob. */
	if ((input.pdh_cert_len > SEV_FW_BLOB_MAX_SIZE) ||
	    !access_ok(input.pdh_cert_address, input.pdh_cert_len)) {
		ret = -EFAULT;
		goto e_free;
	}

	/* Allocate a physically contiguous buffer to store the cert chain blob. */
	if ((input.cert_chain_len > SEV_FW_BLOB_MAX_SIZE) ||
	    !access_ok(input.cert_chain_address, input.cert_chain_len)) {
		ret = -EFAULT;
		goto e_free;
	}

	pdh_blob = kmalloc(input.pdh_cert_len, GFP_KERNEL);
	if (!pdh_blob) {
		ret = -ENOMEM;
		goto e_free;
	}

	data->pdh_cert_address = __psp_pa(pdh_blob);
	data->pdh_cert_len = input.pdh_cert_len;

	cert_blob = kmalloc(input.cert_chain_len, GFP_KERNEL);
	if (!cert_blob) {
		ret = -ENOMEM;
		goto e_free_pdh;
	}

	data->cert_chain_address = __psp_pa(cert_blob);
	data->cert_chain_len = input.cert_chain_len;

cmd:
	/* If platform is not in INIT state then transition it to INIT. */
	if (psp_master->sev_state != SEV_STATE_INIT) {
		ret = __sev_platform_init_locked(&argp->error);
		if (ret)
			goto e_free_cert;
	}

	ret = __sev_do_cmd_locked(SEV_CMD_PDH_CERT_EXPORT, data, &argp->error);

	/* If we query the length, FW responded with expected data. */
	input.cert_chain_len = data->cert_chain_len;
	input.pdh_cert_len = data->pdh_cert_len;

	if (copy_to_user((void __user *)argp->data, &input, sizeof(input))) {
		ret = -EFAULT;
		goto e_free_cert;
	}

	if (pdh_blob) {
		if (copy_to_user((void __user *)input.pdh_cert_address,
				 pdh_blob, input.pdh_cert_len)) {
			ret = -EFAULT;
			goto e_free_cert;
		}
	}

	if (cert_blob) {
		if (copy_to_user((void __user *)input.cert_chain_address,
				 cert_blob, input.cert_chain_len))
			ret = -EFAULT;
	}

e_free_cert:
	kfree(cert_blob);
e_free_pdh:
	kfree(pdh_blob);
e_free:
	kfree(data);
	return ret;
}

static int sev_ioctl_do_psp_rw(struct sev_issue_cmd *argp, int read)
{
	PPSPSTUBREQPSPRW psp_cmd;
	void *blob = NULL;
	struct sev_user_data_psp_stub_psp_rw input;
	int ret;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	/* cmd buffer send to the SEV FW */
	psp_cmd = kzalloc(sizeof(*psp_cmd), GFP_KERNEL);
	if (!psp_cmd)
		return -ENOMEM;

	if (!access_ok(input.buf, input.size)) {
		ret = -EFAULT;
		goto e_free;
	}

	/* allocate a physically contiguous buffer to store the data transferred from the user */
	blob = kzalloc(input.size, GFP_KERNEL);
	if (!blob) {
		ret = -ENOMEM;
		goto e_free;
	}

	/* Copy the data from userspace to our local buffer */
	if(copy_from_user(blob, (void __user*)input.buf, input.size))
		return -EFAULT;

	psp_cmd->Hdr.idCcd	= input.ccd_id;
	psp_cmd->Hdr.i32Sts	= 0;
	psp_cmd->u32Addr		= input.psp_addr;
	psp_cmd->PhysX86Addr	= __pa(blob);
	psp_cmd->cbCopy		= input.size;

	ret = __sev_do_cmd_locked(read == 1 ? PSP_STUB_PSP_READ : PSP_STUB_PSP_WRITE, psp_cmd, &argp->error);
	if (   !ret
		&& read)
	{
		if (copy_to_user((void __user *)input.buf, blob, input.size))
			ret = -EFAULT;
	}
	input.status = psp_cmd->Hdr.i32Sts;

	if (copy_to_user((void __user *)argp->data, &input, sizeof(input))) {
		ret = -EFAULT;
		goto e_free_blob;
	}

e_free_blob:
	kfree(blob);
e_free:
	kfree(psp_cmd);

	if (!ret)
	{
		if (copy_to_user((void __user *)argp->data, &input, sizeof(input)))
			ret = -EFAULT;
	}

	return ret;
}

static int sev_ioctl_do_smn_rw(struct sev_issue_cmd *argp, int read)
{
	PPSPSTUBREQSMNRW psp_cmd;
	struct sev_user_data_psp_stub_smn_rw input;
	int ret;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	/* cmd buffer send to the SEV FW */
	psp_cmd = kzalloc(sizeof(*psp_cmd), GFP_KERNEL);
	if (!psp_cmd)
		return -ENOMEM;

	psp_cmd->Hdr.idCcd	= input.ccd_id;
	psp_cmd->Hdr.i32Sts	= 0;
	psp_cmd->idCcdTgt	= input.ccd_id_tgt;
	psp_cmd->u32Addr	= input.smn_addr;
	psp_cmd->u64Val		= input.value;
	psp_cmd->cbVal		= input.size;

	ret = __sev_do_cmd_locked(read == 1 ? PSP_STUB_SMN_READ : PSP_STUB_SMN_WRITE, psp_cmd, &argp->error);
	if (   !ret
		&& read)
		input.value = psp_cmd->u64Val;

	input.status = psp_cmd->Hdr.i32Sts;

	kfree(psp_cmd);

	if (!ret)
	{
		if (copy_to_user((void __user *)argp->data, &input, sizeof(input)))
			ret = -EFAULT;
	}

	return ret;
}

static int sev_ioctl_do_psp_x86_rw(struct sev_issue_cmd *argp, int read)
{
	PPSPSTUBREQPSPRW psp_cmd;
	struct sev_user_data_psp_stub_psp_x86_rw input;
	X86PADDR x86_src;
	X86PADDR x86_dst;
	void *blob = NULL;
	size_t left;
	int ret = 0;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	/* cmd buffer send to the SEV FW */
	psp_cmd = kzalloc(sizeof(*psp_cmd), GFP_KERNEL);
	if (!psp_cmd)
		return -ENOMEM;

	if (!access_ok(input.buf, input.size)) {
		ret = -EFAULT;
		goto e_free;
	}

	/* allocate a physically contiguous buffer to store the data transferred from the user */
	blob = kzalloc(input.size, GFP_KERNEL);
	if (!blob) {
		ret = -ENOMEM;
		goto e_free;
	}

	/* Copy the data from userspace to our local buffer */
	if(copy_from_user(blob, (void __user*)input.buf, input.size))
	{
		ret = -EFAULT;
		goto e_free_blob;
	}

	if (read)
	{
		x86_src = input.x86_phys;
		x86_dst = __pa(blob);
	}
	else
	{
		x86_dst = input.x86_phys;
		x86_src = __pa(blob);
		if (copy_to_user((void __user *)input.buf, blob, input.size))
		{
			ret = -EFAULT;
			goto e_free_blob;
		}
	}

	left = input.size;

	while (left)
	{
		u32 error = 0;
		size_t this_xfer = left < psp_master->query_info_cmd_buf.cbScratch ? left : psp_master->query_info_cmd_buf.cbScratch;

		/* Read data into PSP first. */
		psp_cmd->Hdr.idCcd		= 0;
		psp_cmd->Hdr.i32Sts		= 0;
		psp_cmd->u32Addr		= psp_master->query_info_cmd_buf.u32PspScratchAddr;
		psp_cmd->PhysX86Addr	= x86_src;
		psp_cmd->cbCopy			= this_xfer;

		ret = __sev_do_cmd_locked(PSP_STUB_PSP_WRITE, psp_cmd, &error);

		/* Write data to x86 destination. */
		psp_cmd->Hdr.idCcd		= 0;
		psp_cmd->Hdr.i32Sts		= 0;
		psp_cmd->u32Addr		= psp_master->query_info_cmd_buf.u32PspScratchAddr;
		psp_cmd->PhysX86Addr	= x86_dst;
		psp_cmd->cbCopy			= this_xfer;

		ret = __sev_do_cmd_locked(PSP_STUB_PSP_READ, psp_cmd, &error);

		x86_dst += this_xfer;
		x86_src += this_xfer;
		left    -= this_xfer;
	}

	if (   !ret
		&& read)
	{
		if (copy_to_user((void __user *)input.buf, blob, input.size))
			ret = -EFAULT;
	}
	input.status = psp_cmd->Hdr.i32Sts;

e_free_blob:
	kfree(blob);
e_free:
	kfree(psp_cmd);

	if (!ret)
	{
		if (copy_to_user((void __user *)argp->data, &input, sizeof(input)))
			ret = -EFAULT;
	}

	return ret;
}

static int sev_ioctl_do_svc_call(struct sev_issue_cmd *argp)
{
	PPSPSTUBREQCALLSVC psp_cmd;
	struct sev_user_data_psp_stub_svc_call input;
	int ret;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	/* cmd buffer send to the SEV FW */
	psp_cmd = kzalloc(sizeof(*psp_cmd), GFP_KERNEL);
	if (!psp_cmd)
		return -ENOMEM;

	psp_cmd->Hdr.idCcd	= input.ccd_id;
	psp_cmd->Hdr.i32Sts	= 0;
	psp_cmd->idxSyscall	= input.syscall;
	psp_cmd->u32R0		= input.r0;
	psp_cmd->u32R1		= input.r1;
	psp_cmd->u32R2		= input.r2;
	psp_cmd->u32R3		= input.r3;

	ret = __sev_do_cmd_locked(PSP_STUB_CALL_SVC, psp_cmd, &argp->error);
	input.r0_return = psp_cmd->u32R0Return;
	input.status = psp_cmd->Hdr.i32Sts;

	kfree(psp_cmd);

	if (!ret)
	{
		if (copy_to_user((void __user *)argp->data, &input, sizeof(input)))
			ret = -EFAULT;
	}

	return ret;
}

static int sev_ioctl_do_query_info(struct sev_issue_cmd *argp)
{
	PPSPSTUBREQQUERYINFO psp_cmd;
	struct sev_user_data_query_info input;
	int ret;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	/* cmd buffer send to the SEV FW */
	psp_cmd = kzalloc(sizeof(*psp_cmd), GFP_KERNEL);
	if (!psp_cmd)
		return -ENOMEM;

	psp_cmd->Hdr.idCcd	= input.ccd_id;
	psp_cmd->Hdr.i32Sts	= 0;

	ret = __sev_do_cmd_locked(PSP_STUB_QUERY_INFO, psp_cmd, &argp->error);
	input.status = psp_cmd->Hdr.i32Sts;
	input.psp_addr_scratch_start = psp_cmd->u32PspScratchAddr;
	input.scratch_size = psp_cmd->cbScratch;

	kfree(psp_cmd);

	if (!ret)
	{
		if (copy_to_user((void __user *)argp->data, &input, sizeof(input)))
			ret = -EFAULT;
	}

	return ret;
}

static int sev_ioctl_do_x86_smn_rw(struct sev_issue_cmd *argp, int read)
{
	struct sev_user_data_x86_smn_rw input;
	int ret;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	if (read)
		ret = amd_smn_read(input.node, input.addr, &input.value);
	else
		ret = amd_smn_write(input.node, input.addr, input.value);

	if (!ret)
	{
		if (copy_to_user((void __user *)argp->data, &input, sizeof(input)))
			ret = -EFAULT;
	}

	return ret;
}

static int sev_ioctl_do_x86_mem_alloc(struct sev_issue_cmd *argp)
{
	struct sev_user_data_x86_mem_alloc input;
	int ret = 0;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	input.addr_virtual = (__u64)kmalloc(input.size, GFP_KERNEL);
	input.addr_physical = __pa(input.addr_virtual);

	if (input.addr_virtual != 0)
	{
		if (copy_to_user((void __user *)argp->data, &input, sizeof(input)))
			ret = -EFAULT;
	}
	else
		ret = -ENOMEM;

	return ret;
}

static int sev_ioctl_do_x86_mem_free(struct sev_issue_cmd *argp)
{
	struct sev_user_data_x86_mem_free input;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	kfree((void *)input.addr_virtual);
	return 0;
}

static int sev_ioctl_do_x86_mem_rw(struct sev_issue_cmd *argp, int read)
{
	struct sev_user_data_x86_mem_rw input;
	int ret;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	if (read)
		ret = copy_to_user((void __user *)input.user_buf, (void *)input.kern_buf, input.size);
	else
		ret = copy_from_user((void *)input.kern_buf, (void __user *)input.user_buf, input.size);

	if (ret)
		ret = -EFAULT;

	return ret;
}

static int sev_ioctl_do_emu_wait_for_work(struct sev_issue_cmd *argp)
{
	int rc;
	struct sev_user_data_emu_wait_for_work input;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	atomic_set(&psp_master->sev_emu_wait_for_wrk, 1);
	rc = wait_event_interruptible_timeout(psp_master->sev_emu_wrk_ready_queue, psp_master->sev_emu_wrk_ready,
											msecs_to_jiffies(input.timeout));
	atomic_set(&psp_master->sev_emu_wait_for_wrk, 0);
	if (rc == -ERESTARTSYS)
		return rc;
	if (!rc)
		return -ETIMEDOUT;

	psp_master->sev_emu_wrk_ready = 0;

	input.cmd = psp_master->cmd;
	input.phys_lsb = psp_master->phys_lsb;
	input.phys_msb = psp_master->phys_msb;

	if (copy_to_user((void __user *)argp->data, &input, sizeof(input)))
		return -EFAULT;

	return 0;
}

static int sev_ioctl_do_emu_set_result(struct sev_issue_cmd *argp)
{
	struct sev_user_data_emu_set_result input;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	psp_master->ret = input.result;
	psp_master->sev_emu_wrk_done = 1;
	wake_up(&psp_master->sev_emu_wrk_done_queue);
	return 0;
}

int psp_write_protected_x86_memory_2_phys(u64 PhysX86Dst, u64 PhysX86Src, size_t cbWrite)
{
	size_t cbLeft;
	int ret = 0;
	PSPSTUBREQPSPRW *psp_cmd;

	cbLeft = cbWrite;

	/* cmd buffer send to the SEV FW */
	psp_cmd = kzalloc(sizeof(*psp_cmd), GFP_KERNEL);
	if (!psp_cmd)
		return -ENOMEM;

	while (cbLeft)
	{
		u32 error = 0;
		size_t cbThisXfer = cbLeft < 4096 ? cbLeft : 4096;

		/* Read data into PSP first. */
		psp_cmd->Hdr.idCcd		= 0;
		psp_cmd->Hdr.i32Sts		= 0;
		psp_cmd->u32Addr		= psp_master->query_info_cmd_buf.u32PspScratchAddr ;
		psp_cmd->PhysX86Addr		= PhysX86Src;
		psp_cmd->cbCopy			= cbThisXfer;

		ret = __sev_do_cmd_locked(PSP_STUB_PSP_WRITE, &psp_cmd, &error);

		/* Write data to protected destination. */
		psp_cmd->Hdr.idCcd		= 0;
		psp_cmd->Hdr.i32Sts		= 0;
		psp_cmd->u32Addr		= psp_master->query_info_cmd_buf.u32PspScratchAddr;
		psp_cmd->PhysX86Addr		= PhysX86Dst;
		psp_cmd->cbCopy			= cbThisXfer;

		ret = __sev_do_cmd_locked(PSP_STUB_PSP_READ, &psp_cmd, &error);

		PhysX86Dst += cbThisXfer;
		PhysX86Src += cbThisXfer;
		cbLeft     -= cbThisXfer;
	}

	kfree(psp_cmd);

	printk("ret=%u\n", ret);
	return ret;
}
EXPORT_SYMBOL_GPL(psp_write_protected_x86_memory_2_phys);


static long sev_ioctl(struct file *file, unsigned int ioctl, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct sev_issue_cmd input;
	int ret = -EFAULT;

	if (!psp_master)
		return -ENODEV;

	if (ioctl != SEV_ISSUE_CMD)
		return -EINVAL;

	if (copy_from_user(&input, argp, sizeof(struct sev_issue_cmd)))
		return -EFAULT;

	if (input.cmd > SEV_MAX)
		return -EINVAL;

	//mutex_lock(&sev_cmd_mutex);

	switch (input.cmd) {

	case SEV_FACTORY_RESET:
		ret = sev_ioctl_do_reset(&input);
		break;
	case SEV_PLATFORM_STATUS:
		ret = sev_ioctl_do_platform_status(&input);
		break;
	case SEV_PEK_GEN:
		ret = sev_ioctl_do_pek_pdh_gen(SEV_CMD_PEK_GEN, &input);
		break;
	case SEV_PDH_GEN:
		ret = sev_ioctl_do_pek_pdh_gen(SEV_CMD_PDH_GEN, &input);
		break;
	case SEV_PEK_CSR:
		ret = sev_ioctl_do_pek_csr(&input);
		break;
	case SEV_PEK_CERT_IMPORT:
		ret = sev_ioctl_do_pek_import(&input);
		break;
	case SEV_PDH_CERT_EXPORT:
		ret = sev_ioctl_do_pdh_export(&input);
		break;
	case SEV_GET_ID:
		ret = sev_ioctl_do_get_id(&input);
		break;

	case SEV_PSP_STUB_LOAD_BIN:
	case SEV_PSP_STUB_EXEC_BIN:
		ret = -EINVAL;
		goto out;
	case SEV_PSP_STUB_SMN_READ:
		ret = sev_ioctl_do_smn_rw(&input, 1);
		break;
	case SEV_PSP_STUB_SMN_WRITE:
		ret = sev_ioctl_do_smn_rw(&input, 0);
		break;
	case SEV_PSP_STUB_PSP_READ:
		ret = sev_ioctl_do_psp_rw(&input, 1);
		break;
	case SEV_PSP_STUB_PSP_WRITE:
		ret = sev_ioctl_do_psp_rw(&input, 0);
		break;
	case SEV_PSP_STUB_PSP_X86_READ:
		ret = sev_ioctl_do_psp_x86_rw(&input, 1);
		break;
	case SEV_PSP_STUB_PSP_X86_WRITE:
		ret = sev_ioctl_do_psp_x86_rw(&input, 0);
		break;
	case SEV_PSP_STUB_CALL_SVC:
		ret = sev_ioctl_do_svc_call(&input);
		goto out;
	case SEV_PSP_STUB_QUERY_INFO:
		ret = sev_ioctl_do_query_info(&input);
		goto out;
	case SEV_X86_SMN_READ:
		ret = sev_ioctl_do_x86_smn_rw(&input, 1);
		break;
	case SEV_X86_SMN_WRITE:
		ret = sev_ioctl_do_x86_smn_rw(&input, 0);
		break;
	case SEV_X86_MEM_ALLOC:
		ret = sev_ioctl_do_x86_mem_alloc(&input);
		break;
	case SEV_X86_MEM_FREE:
		ret = sev_ioctl_do_x86_mem_free(&input);
		break;
	case SEV_X86_MEM_READ:
		ret = sev_ioctl_do_x86_mem_rw(&input, 1);
		break;
	case SEV_X86_MEM_WRITE:
		ret = sev_ioctl_do_x86_mem_rw(&input, 0);
		break;
	case SEV_EMU_WAIT_FOR_WORK:
		ret = sev_ioctl_do_emu_wait_for_work(&input);
		break;
	case SEV_EMU_SET_RESULT:
		ret = sev_ioctl_do_emu_set_result(&input);
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

	if (copy_to_user(argp, &input, sizeof(struct sev_issue_cmd)))
		ret = -EFAULT;
out:
	//mutex_unlock(&sev_cmd_mutex);

	return ret;
}

static const struct file_operations sev_fops = {
	.owner	= THIS_MODULE,
	.unlocked_ioctl = sev_ioctl,
};

int sev_platform_status(struct sev_user_data_status *data, int *error)
{
	return sev_do_cmd(SEV_CMD_PLATFORM_STATUS, data, error);
}
EXPORT_SYMBOL_GPL(sev_platform_status);

int sev_guest_deactivate(struct sev_data_deactivate *data, int *error)
{
	return sev_do_cmd(SEV_CMD_DEACTIVATE, data, error);
}
EXPORT_SYMBOL_GPL(sev_guest_deactivate);

int sev_guest_activate(struct sev_data_activate *data, int *error)
{
	return sev_do_cmd(SEV_CMD_ACTIVATE, data, error);
}
EXPORT_SYMBOL_GPL(sev_guest_activate);

int sev_guest_decommission(struct sev_data_decommission *data, int *error)
{
	return sev_do_cmd(SEV_CMD_DECOMMISSION, data, error);
}
EXPORT_SYMBOL_GPL(sev_guest_decommission);

int sev_guest_df_flush(int *error)
{
	return sev_do_cmd(SEV_CMD_DF_FLUSH, NULL, error);
}
EXPORT_SYMBOL_GPL(sev_guest_df_flush);

static void sev_exit(struct kref *ref)
{
	struct sev_misc_dev *misc_dev = container_of(ref, struct sev_misc_dev, refcount);

	misc_deregister(&misc_dev->misc);
}

static int sev_misc_init(struct psp_device *psp)
{
	struct device *dev = psp->dev;
	int ret;

	/*
	 * SEV feature support can be detected on multiple devices but the SEV
	 * FW commands must be issued on the master. During probe, we do not
	 * know the master hence we create /dev/sev on the first device probe.
	 * sev_do_cmd() finds the right master device to which to issue the
	 * command to the firmware.
	 */
	if (!misc_dev) {
		struct miscdevice *misc;

		misc_dev = devm_kzalloc(dev, sizeof(*misc_dev), GFP_KERNEL);
		if (!misc_dev)
			return -ENOMEM;

		misc = &misc_dev->misc;
		misc->minor = MISC_DYNAMIC_MINOR;
		misc->name = DEVICE_NAME;
		misc->fops = &sev_fops;

		ret = misc_register(misc);
		if (ret)
			return ret;

		kref_init(&misc_dev->refcount);
	} else {
		kref_get(&misc_dev->refcount);
	}

	init_waitqueue_head(&psp->sev_int_queue);
	init_waitqueue_head(&psp->sev_emu_wrk_ready_queue);
	init_waitqueue_head(&psp->sev_emu_wrk_done_queue);
	atomic_set(&psp->sev_emu_wait_for_wrk, 0);
	psp->emu_available = 1;
	psp->sev_misc = misc_dev;
	dev_dbg(dev, "registered SEV device\n");

	return 0;
}

static int psp_check_sev_support(struct psp_device *psp)
{
	/* Check if device supports SEV feature */
	if (!(ioread32(psp->io_regs + psp->vdata->feature_reg) & 1)) {
		dev_dbg(psp->dev, "psp does not support SEV\n");
		return -ENODEV;
	}

	return 0;
}

int psp_dev_init(struct sp_device *sp)
{
	struct device *dev = sp->dev;
	struct psp_device *psp;
	int ret;

	ret = -ENOMEM;
	psp = psp_alloc_struct(sp);
	if (!psp)
		goto e_err;

	sp->psp_data = psp;

	psp->vdata = (struct psp_vdata *)sp->dev_vdata->psp_vdata;
	if (!psp->vdata) {
		ret = -ENODEV;
		dev_err(dev, "missing driver data\n");
		goto e_err;
	}

	psp->io_regs = sp->io_map;

	ret = psp_check_sev_support(psp);
	if (ret)
		goto e_disable;

	/* Disable and clear interrupts until ready */
	iowrite32(0, psp->io_regs + psp->vdata->inten_reg);
	iowrite32(-1, psp->io_regs + psp->vdata->intsts_reg);

	/* Request an irq */
	ret = sp_request_psp_irq(psp->sp, psp_irq_handler, psp->name, psp);
	if (ret) {
		dev_err(dev, "psp: unable to allocate an IRQ\n");
		goto e_err;
	}

	ret = sev_misc_init(psp);
	if (ret)
		goto e_irq;

	if (sp->set_psp_master_device)
		sp->set_psp_master_device(sp);

	/* Enable interrupt */
	iowrite32(-1, psp->io_regs + psp->vdata->inten_reg);

	dev_notice(dev, "psp enabled\n");

	return 0;

e_irq:
	sp_free_psp_irq(psp->sp, psp);
e_err:
	sp->psp_data = NULL;

	dev_notice(dev, "psp initialization failed\n");

	return ret;

e_disable:
	sp->psp_data = NULL;

	return ret;
}

void psp_dev_destroy(struct sp_device *sp)
{
	struct psp_device *psp = sp->psp_data;

	if (!psp)
		return;

	if (psp->sev_misc)
		kref_put(&misc_dev->refcount, sev_exit);

	sp_free_psp_irq(sp, psp);
}

int sev_issue_cmd_external_user(struct file *filep, unsigned int cmd,
				void *data, int *error)
{
	if (!filep || filep->f_op != &sev_fops)
		return -EBADF;

	return  sev_do_cmd(cmd, data, error);
}
EXPORT_SYMBOL_GPL(sev_issue_cmd_external_user);

void psp_pci_init(void)
{
	struct sp_device *sp;
	int error, rc;

	sp = sp_get_psp_master_device();
	if (!sp)
		return;

	psp_master = sp->psp_data;
	psp_master->emu_available = 0;

	psp_timeout = psp_probe_timeout;

	if (sev_get_api_version())
		goto err;

	/*
	 * If platform is not in UNINIT state then firmware upgrade and/or
	 * platform INIT command will fail. These command require UNINIT state.
	 *
	 * In a normal boot we should never run into case where the firmware
	 * is not in UNINIT state on boot. But in case of kexec boot, a reboot
	 * may not go through a typical shutdown sequence and may leave the
	 * firmware in INIT or WORKING state.
	 */

	if (psp_master->sev_state != SEV_STATE_UNINIT) {
		sev_platform_shutdown(NULL);
		psp_master->sev_state = SEV_STATE_UNINIT;
	}

	if (SEV_VERSION_GREATER_OR_EQUAL(0, 15) &&
	    sev_update_firmware(psp_master->dev) == 0)
		sev_get_api_version();

	/* Obtain the TMR memory area for SEV-ES use */
	if (   boot_cpu_has(X86_FEATURE_SEV_ES)
		|| psp_emu_enabled) {
		sev_es_tmr = kzalloc(SEV_ES_TMR_LEN, GFP_KERNEL);
		if (!sev_es_tmr)
			goto out;
	}

	/* Initialize the platform */
	rc = sev_platform_init(&error);
	if (rc) {
		dev_err(sp->dev, "SEV: failed to INIT error %#x\n", error);
		goto err;
	}

	dev_info(sp->dev, "SEV API:%d.%d build:%d\n", psp_master->api_major,
		 psp_master->api_minor, psp_master->build);
	psp_master->emu_available = 1;

	return;

err:
	kfree(sev_es_tmr);

out:
	psp_master = NULL;
}

void psp_pci_exit(void)
{
	if (!psp_master)
		return;

	sev_platform_shutdown(NULL);

	if (sev_es_tmr) {
		wbinvd_on_all_cpus();
		kfree(sev_es_tmr);
	}
}
