#ifndef RILFWD_H
#define RILFWD_H

#define AID_RADIO 1001
#define MAX_CAP_NUM (CAP_TO_INDEX(CAP_LAST_CAP) + 1)

#ifdef __cplusplus
extern "C" {
#include <unistd.h>
#include "common/logf.h"
#endif

typedef struct {
	char *type;
	char *ifname;
	size_t addresses_len;
	char **addresses;
	size_t dnses_len;
	char **dnses;
	size_t gateways_len;
	char **gateways;
	char *pcscf;
	
} iface_cfg_t;

iface_cfg_t *
parse_data_call(char *data, size_t parcelsize);

void
iface_cfg_free(iface_cfg_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* RILFWD_H */
