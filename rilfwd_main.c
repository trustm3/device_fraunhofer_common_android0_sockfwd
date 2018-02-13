/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2017 Fraunhofer AISEC
 * Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 (GPL 2), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GPL 2 license for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Contact Information:
 * Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
 */

#define LOGF_LOG_MIN_PRIO 2

#include "common/macro.h"
#include "common/mem.h"
#include "common/event.h"
#include "common/network.h"
#include "common/file.h"

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/prctl.h>

#include "sockfwd.h"
#include "rilfwd.h"

#define RESOLV_CONF "/data/misc/dhcp/dnsmasq.resolv.conf"
#define DNSMASQ_PID_FILE "/data/misc/dhcp/dnsmasq.pid"

static char *progname = NULL;
static event_timer_t *net_setup_timer = NULL;

/******************************************************************************/

static void
main_core_dump_enable(void)
{
	struct rlimit core_limit;

	core_limit.rlim_cur = RLIM_INFINITY;
	core_limit.rlim_max = RLIM_INFINITY;

	if (setrlimit(RLIMIT_CORE, &core_limit) < 0)
		ERROR_ERRNO("Could not set rlimits for core dump generation");
}

static void
main_sig_cb(UNUSED int signum, UNUSED event_signal_t *sig, UNUSED void *data)
{
	FATAL("Received SIGINT...");
}

/******************************************************************************/

/*
 * Switches UID to radio, preserving CAP_NET_SETUID capability.
 * This is needed for running network config with the iprout2 ip tool.
 */
static void
switch_user(void)
{
	prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
	if (setresuid(AID_RADIO, AID_RADIO, AID_RADIO) == -1) {
		FATAL_ERRNO("setresuid failed");
	}

	struct __user_cap_header_struct header;
	memset(&header, 0, sizeof(header));
	header.version = _LINUX_CAPABILITY_VERSION_3;
	header.pid = 0;

	struct __user_cap_data_struct data[MAX_CAP_NUM];
	memset(&data, 0, sizeof(data));

	data[CAP_TO_INDEX(CAP_NET_ADMIN)].effective |= CAP_TO_MASK(CAP_NET_ADMIN);
	data[CAP_TO_INDEX(CAP_NET_ADMIN)].permitted |= CAP_TO_MASK(CAP_NET_ADMIN);
	data[CAP_TO_INDEX(CAP_NET_ADMIN)].inheritable |= CAP_TO_MASK(CAP_NET_ADMIN);

	data[CAP_TO_INDEX(CAP_NET_RAW)].effective |= CAP_TO_MASK(CAP_NET_RAW);
	data[CAP_TO_INDEX(CAP_NET_RAW)].permitted |= CAP_TO_MASK(CAP_NET_RAW);
	data[CAP_TO_INDEX(CAP_NET_RAW)].inheritable |= CAP_TO_MASK(CAP_NET_RAW);

	data[CAP_TO_INDEX(CAP_SETUID)].effective |= CAP_TO_MASK(CAP_SETUID);
	data[CAP_TO_INDEX(CAP_SETUID)].permitted |= CAP_TO_MASK(CAP_SETUID);
	data[CAP_TO_INDEX(CAP_SETUID)].inheritable |= CAP_TO_MASK(CAP_SETUID);

	if (capset(&header, &data[0]) == -1) {
		FATAL("capset failed");
	}
}

#ifdef DNSMASQ_SYNC_ENABLED
static pid_t
get_pid_from_file(const char *file_name)
{
	FILE *pid_file;
	pid_t pid;

	pid_file = fopen(file_name, "r");
	if (pid_file == NULL)
		return 0;

	if (fscanf(pid_file, "%d", &pid) <= 0) {
		fclose(pid_file);
		return 0;
	}

	fclose(pid_file);
	return pid;
}
#endif

static int
rilfwd_main_network_init(void)
{
	// enable nat for local networks which are routed over
	// mobile data connection
	//for (int i=2; i<255; i++) {
	//	char *subnet = mem_printf("127.%d.0.0/16", i);
	//	if (network_setup_masquerading(subnet, true)) {
	//		mem_free(subnet);
	//		return -1;
	//	}
	//	mem_free(subnet);
	//}
	int retry = 0;
	while (network_setup_masquerading("127.0.0.0/8", true)) {
		if (++retry == 10) {
			ERROR("Failed to setup masquerading!");
			return -1;
		}
	}
	DEBUG("Setup masquerading after %d retries done.", retry);

	// flush routing rules and set main table as default table
	if (network_routing_rules_set_all_main(true))
		ERROR("Faild to setup routing rules!");

	return 0;
}

static void
rilfwd_main_network_setup_cb(event_timer_t *timer, void *data)
{
	ASSERT(timer == net_setup_timer);
	ASSERT(data);
	iface_cfg_t *cfg = data;

	if (strcmp(cfg->type, "IP"))
		ERROR("Type %s not supported, we only support type IP!", cfg->type);

	/* print iface info */
	INFO("Setup for interface %s", cfg->ifname);
	for (size_t i=0; i<cfg->addresses_len; ++i)
		DEBUG("\t addresses[%zu]: %s", i, cfg->addresses[i]);
	for (size_t i=0; i<cfg->dnses_len; ++i)
		DEBUG("\t dnses[%zu]: %s", i, cfg->dnses[i]);
	for (size_t i=0; i<cfg->gateways_len; ++i)
		DEBUG("\t gateways[%zu]: %s", i, cfg->gateways[i]);

	/* do network setup */
	if (cfg->gateways_len > 0) {
		if(network_setup_default_route(cfg->gateways[0], true)) {
			ERROR("Failed to setup default route via %s", cfg->gateways[0]);
			return;
		}
		DEBUG("Setup route done.");
	}

#ifdef DNSMASQ_SYNC_ENABLED
	file_printf(RESOLV_CONF, "# auto-generated config by %s", progname);
	for (size_t i=0; i<cfg->dnses_len; ++i) {
		file_printf_append(RESOLV_CONF, "nameserver %s\n", cfg->dnses[i]);
	}

	// Inform dnsmasq about change of resolv.conf
	pid_t pid = get_pid_from_file(DNSMASQ_PID_FILE);
	if (!pid) {
		WARN_ERRNO("cannot read dnsmasq's pid_file!");
		goto out;
	}
	// SIGHUP causes dnsmasq ro re-read resolv.conf if dnsmasq is runnign with --no-poll
	if (kill(pid, SIGHUP))
		WARN_ERRNO("cannot reload dnsmasq!");

out:
#endif
	iface_cfg_free(cfg);
	event_remove_timer(timer);
	event_timer_free(timer);
	net_setup_timer = NULL;
}

static void
rilfwd_log_ril_data(char *data, size_t parcelsize)
{
	char *output = mem_new0(char, (parcelsize * 3) + 20);

	sprintf(output, "size: %zu pdata: %02x", parcelsize, *data++);
	for (size_t i = 1; i < parcelsize; i++) {
		sprintf(output, "%s %02x", output, *data++);
	}
	TRACE("%s", output);
	mem_free(output);
}


static uint32_t data_call_serial = 0;

static void
rilfwd_main_datacall_cb(char *raw_msg, size_t raw_msg_len)
{
	TRACE("Data Callback called");

	if (raw_msg_len < sizeof(uint32_t)*2) {
		DEBUG("Rilparcel not complete, returning...");
		return;
	}

	uint32_t msg_param0 = *(uint32_t*)(raw_msg);
	uint32_t msg_param1 = *(uint32_t*)(raw_msg+4);
	uint32_t msg_param2 = *(uint32_t*)(raw_msg+8);

	switch(msg_param0) {
		case 0: // RIL SOL RESPONSE
			if (msg_param1 == data_call_serial) {
				DEBUG("RIL_RESP_SETUP_DATA_CALL serial=%d", msg_param1);
				rilfwd_log_ril_data(raw_msg, raw_msg_len);
				if (msg_param2 == 0) { // ERROR CODE SUCCESS
					iface_cfg_t *config =
						parse_data_call(raw_msg+12, raw_msg_len-12);
					if (config) {
						if (net_setup_timer) {
							event_remove_timer(net_setup_timer);
							event_timer_free(net_setup_timer);
						}
						net_setup_timer = 
							event_timer_new(500, 10, rilfwd_main_network_setup_cb, config);
						event_add_timer(net_setup_timer);
					}
				}
				data_call_serial = 0;
			}
			break;
		case 1: // RIL UNSOL MSG
			if (msg_param1 == 1010) { // RIL_UNSOL_DATA_CALL_LIST_CHANGED
				DEBUG("RIL_UNSOL_DATA_CALL_LIST_CHANGED");
				rilfwd_log_ril_data(raw_msg, raw_msg_len);
				iface_cfg_t *config = parse_data_call(raw_msg+8, raw_msg_len-8);
				if (config) {
					if (net_setup_timer) {
						event_remove_timer(net_setup_timer);
						event_timer_free(net_setup_timer);
					}
					net_setup_timer = 
						event_timer_new(500, 10, rilfwd_main_network_setup_cb, config);
					event_add_timer(net_setup_timer);
				}
			}
			break;
		case 27: // RIL_REQUEST_SETUP_DATA_CALL
			DEBUG("RIL_REQUEST_SETUP_DATA_CALL serial=%d", msg_param1);
			data_call_serial = msg_param1;
			rilfwd_log_ril_data(raw_msg, raw_msg_len);
			break;
	}
}

int
main(int argc, char **argv)
{
	logf_handler_t *h;

	h = logf_register(&logf_android_write, logf_android_new(argv[0]));
	logf_handler_set_prio(h, LOGF_PRIO_TRACE);

	h = logf_register(&logf_file_write, stdout);
	logf_handler_set_prio(h, LOGF_PRIO_TRACE);

	main_core_dump_enable();

	INFO("Starting rilfwd ...");

	ASSERT(argc == 3);

	progname = argv[0];
	char *path_listen = argv[1];
	char *path_client_src = argv[2];

	if (rilfwd_main_network_init())
		FATAL("Could not configure network!");

	switch_user();

	event_init();

	event_signal_t *sig_int = event_signal_new(SIGINT, &main_sig_cb, NULL);
	event_add_signal(sig_int);

	return sockfwd_run(path_listen, path_client_src, &rilfwd_main_datacall_cb);
}

