#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>

#include "shared_macros.h"
#include "config_api.h"

#define TB_CONFIG_FILE  "/root/thingsboard-gateway-2.7/thingsboard_gateway/config/tb_gateway.yaml"

int save_apply_thingsboard()
{
	char *newline;
	char tmp[100];
	unsigned short tmplen;
	int rc;
	int i;
	FILE *fp;
	char cmdline[512];

	// sed -i 's/.* host:.*/  host: xxxxx/' config/tb_gateway.yaml

	cmdline[0] = 0;
	strcat(cmdline, "sed -i 's/.* host:.*/  host: ");
	tmp[0] = 0;
	rc = config_get("mqtt-gw", "server", "host", tmp, &tmplen);
	printf("host is %s --%d --%d\n", tmp,  tmplen, rc);
	if (rc !=0 ) {
		return -1;
	}
	strcat(cmdline, tmp);
	strcat(cmdline, "/' ");
	strcat(cmdline, TB_CONFIG_FILE);
	system(cmdline);

	cmdline[0] = 0;
	strcat(cmdline, "sed -i 's/.* port:.*/  port: ");
	tmp[0] = 0;
	rc = config_get("mqtt-gw", "server", "port", tmp, &tmplen);
	printf("port is %s --%d --%d\n", tmp,  tmplen, rc);
	if (rc !=0 ) {
		return -1;
	}
	strcat(cmdline, tmp);
	strcat(cmdline, "/' ");
	strcat(cmdline, TB_CONFIG_FILE);
	system(cmdline);

	cmdline[0] = 0;
	strcat(cmdline, "sed -i 's/.* accessToken:.*/    accessToken: ");
	tmp[0] = 0;
	rc = config_get("mqtt-gw", "server", "accessToken", tmp, &tmplen);
	printf("accessToken is %s --%d --%d\n", tmp,  tmplen, rc);
	if (rc !=0 ) {
		return -1;
	}
	strcat(cmdline, tmp);
	strcat(cmdline, "/' ");
	strcat(cmdline, TB_CONFIG_FILE);
	system(cmdline);

	// TODO
	// reconnect to TB
 
	return 0;
}


#if 0

int main()
{
}
#endif


