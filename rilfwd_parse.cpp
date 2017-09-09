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

#include "rilfwd.h"

#include <binder/Parcel.h>
#include <cutils/jstring.h>
#include <string.h>

extern "C" {
#include "common/macro.h"
#include "common/mem.h"
}

namespace android {

static char *
strdupReadString(Parcel &p) {
    size_t stringlen;
    const char16_t *s16;

    s16 = p.readString16Inplace(&stringlen);

    return strndup16to8(s16, stringlen);
}

extern "C" void
iface_cfg_free(iface_cfg_t *cfg)
{
	if (cfg->type)
		mem_free(cfg->type);
	if (cfg->ifname)
		mem_free(cfg->ifname);
	for (size_t i=0; i<cfg->addresses_len; ++i)
		mem_free(cfg->addresses[i]);
	mem_free(cfg->addresses);
	for (size_t i=0; i<cfg->dnses_len; ++i)
		mem_free(cfg->dnses[i]);
	mem_free(cfg->dnses);
	for (size_t i=0; i<cfg->gateways_len; ++i)
		mem_free(cfg->gateways[i]);
	mem_free(cfg->gateways);
	if (cfg->pcscf)
       		mem_free(cfg->pcscf);
}

extern "C" iface_cfg_t *
parse_data_call(char *data, size_t parcelsize)
{
	Parcel p;
	p.setData((uint8_t *) data, parcelsize);
	status_t status;

	int version;
	int num;

       	status = p.readInt32(&version);
    	if (status != NO_ERROR) {
        	ERROR("Invalid version!");
		return NULL;
    	}
	if (version < 6) {
		ERROR("Version %d not supported, we only support RIL_Data_Call_Response_v6 and newer", version);
		return NULL;
	}
	DEBUG("Version V%d", version);

    	status = p.readInt32(&num);
    	if (status != NO_ERROR) {
        	ERROR("Invalid num!");
		return NULL;
    	}

	int _status;
	int suggestedRetryTime;
	int cid;
	int active;
	char *type = NULL;
	char *ifname = NULL;
	char *addresses = NULL;
	char *dnses = NULL;
	char *gateways = NULL;
	char *pcscf = NULL;
	int mtu;

	for (int i = 0; i < num; i++) {
    		status = p.readInt32(&_status);
    		if (status != NO_ERROR) {
        		ERROR("Invalid status!");
			return NULL;
    		}
    		status = p.readInt32(&suggestedRetryTime);
    		if (status != NO_ERROR) {
        		ERROR("Invalid suggestedRetryTime!");
			return NULL;
    		}
    		status = p.readInt32(&cid);
    		if (status != NO_ERROR) {
        		ERROR("Invalid cid!");
			return NULL;
    		}
    		status = p.readInt32(&active);
    		if (status != NO_ERROR) {
        		ERROR("Invalid active!");
			return NULL;
    		}

		if (type) mem_free(type);
		if (ifname) mem_free(ifname);
		if (addresses) mem_free(addresses);
		if (dnses) mem_free(dnses);
		if (gateways) mem_free(gateways);

		type = strdupReadString(p);
		ifname = strdupReadString(p);
		addresses = strdupReadString(p);
		dnses = strdupReadString(p);
		gateways = strdupReadString(p);
	
		DEBUG("DATA_CALL_RSP: status=%d, suggestedRetryTime=%d, cid=%d, active=%d",
				_status, suggestedRetryTime, cid, active);
		DEBUG("\t type=%s, ifname=%s", type, ifname);
		DEBUG("\t addresses=%s, ifname=%s", addresses, ifname);
		DEBUG("\t dnses=%s, gateways=%s", dnses, gateways);

		if (version > 9) {
			if (pcscf) mem_free(pcscf);
			pcscf = strdupReadString(p);
			DEBUG("\t pcscf=%s", pcscf);
		}

		if (version > 10) {
    			status = p.readInt32(&mtu);
    			if (status != NO_ERROR) {
        			ERROR("Invalid mtu!");
				return NULL;
    			}
			DEBUG("\t mtu=%d", mtu);
		}

		if (strlen(dnses) && strlen(gateways)) break;

	}
	
	iface_cfg_t *ifcfg = mem_new0(iface_cfg_t, 1);
	ifcfg->type = type;
	ifcfg->ifname = ifname;
	
	char *ptr = strtok(addresses, " ");
	ifcfg->addresses_len = 0;
	ifcfg->addresses = mem_new0(char*, 1);
	while (ptr != NULL) {
		ifcfg->addresses[ifcfg->addresses_len] = mem_strdup(ptr);
		ptr = strtok(NULL, " ");
		ifcfg->addresses_len++;
	}
	ptr = strtok(dnses, " ");
	ifcfg->dnses_len = 0;
	ifcfg->dnses = mem_new0(char*, 1);
       	while (ptr != NULL) {
		ifcfg->dnses[ifcfg->dnses_len] = mem_strdup(ptr);
		ptr = strtok(NULL, " ");
		ifcfg->dnses_len++;
	}
	ptr = strtok(gateways, " ");
	ifcfg->gateways_len = 0;
	ifcfg->gateways = mem_new0(char*, 1);
	while (ptr != NULL) {
		ifcfg->gateways[ifcfg->gateways_len] = mem_strdup(ptr);
		ptr = strtok(NULL, " ");
		ifcfg->gateways_len++;
	}

	ifcfg->pcscf = pcscf;

	mem_free(addresses);
	mem_free(dnses);
	mem_free(gateways);

	return ifcfg;
}

} /* namespace android */
