#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>

#include "shared_macros.h"
#include "config_api.h"

#define MAX_LAN_CONF_LINES  50
static char* dnsmasq_conf_lines[MAX_LAN_CONF_LINES];
static char* intf_conf_lines[MAX_LAN_CONF_LINES];

static int read_intf_config()
{
	FILE *fp;
	char *line = NULL;
	int lines = 0;
	size_t len;
	ssize_t read;

	memset(intf_conf_lines, 0, sizeof(intf_conf_lines));
	fp = fopen(NETIF_CONFIG_FILE, "r");
	while ((read = getline(&line, &len, fp)) > 0) {
		line[read-1]='\0';
		//printf("[line %d, len %ld] %s\n", lines, read, line);
		intf_conf_lines[lines] = strdup(line);
		lines++;
		if (lines >= MAX_LAN_CONF_LINES) {
			exit(-1);
		}
	}
	if (line)
		free(line);
	fclose(fp);
	return 0;
}

int save_new_lan_config()
{
	char *newline;
	char tmp[100];
	unsigned short tmplen;
	int rc;
	int i;
	int wlan_ip = -1;
	int wlan_mask = -1;
	FILE *fp;
	int found_wlan = 0;

	//printf("\n\nGenerate new config:\n");

	//======== 1. first change dnsmasq setting 
	tmp[0] = 0;
	rc = config_get("network", "lan", "ipaddr", tmp, &tmplen);
	//printf("ipaddr is %s --%d --%d\n", tmp,  tmplen, rc);
	if (rc !=0 ) {
		return -1;
	}
	newline = malloc(256);
	newline[0] = 0;
	strcat(newline, "dhcp-option=3,");
	strcat(newline, tmp);
	dnsmasq_conf_lines[4] = newline;

	for (i=strlen(tmp); i>0; i--) {
		if (tmp[i-1] == '.') {
			tmp[i-1] = 0;
			break;
		}
	}
	newline = malloc(256);
	newline[0] = 0;
	strcat(newline, "dhcp-range=");
	strcat(newline, tmp);
	strcat(newline, ".100,");
	strcat(newline, tmp);
	strcat(newline, ".200,6h");
	dnsmasq_conf_lines[3] = newline;

	dnsmasq_conf_lines[0] = "interface=wlan0";
	dnsmasq_conf_lines[1] = "bind-interfaces";
	dnsmasq_conf_lines[2] = "except-interface=lo";

	// save to file
	fp = fopen(DNSMASQ_CONFIG_FILE, "w");
	for (i=0; i<MAX_LAN_CONF_LINES; i++) {
		if (dnsmasq_conf_lines[i] == NULL) {
			break;
		}
		fwrite(dnsmasq_conf_lines[i], strlen(dnsmasq_conf_lines[i]), 1, fp);
		fwrite("\n", 1, 1, fp);
	}
	fclose(fp);
	free(dnsmasq_conf_lines[3]);
	free(dnsmasq_conf_lines[4]);

	//========= 2. now change network/interfaces
	read_intf_config();
	for (i=0; i<MAX_LAN_CONF_LINES; i++) {
		if (intf_conf_lines[i] == NULL) {
			break;
		}
		if (strcmp(intf_conf_lines[i], "auto wlan0") == 0) {
			found_wlan = 1;
		}
		if (found_wlan) {
			if (strncmp(intf_conf_lines[i], "address", 7) == 0) {
				wlan_ip = i;
			} else if (strncmp(intf_conf_lines[i], "netmask", 7) == 0) {
				wlan_mask = i;
			}
			if (wlan_ip >= 0 && wlan_mask >= 0) {
				// both found
				break;
			}
		}
	}
	// then replace wlan setting
	tmp[0] = 0;
	rc = config_get("network", "lan", "ipaddr", tmp, &tmplen);
	//printf("ipaddr is %s --%d --%d\n", tmp,  tmplen, rc);
	if (rc !=0 ) {
		return -1;
	}
	newline = malloc(256);
	newline[0] = 0;
	strcat(newline, "address ");
	strcat(newline, tmp);
	free(intf_conf_lines[wlan_ip]);
	intf_conf_lines[wlan_ip] = newline;

	tmp[0] = 0;
	rc = config_get("network", "lan", "netmask", tmp, &tmplen);
	//printf("netmask is %s --%d --%d\n", tmp,  tmplen, rc);
	if (rc !=0 ) {
		free(intf_conf_lines[wlan_ip]);
		return -1;
	}
	newline = malloc(256);
	newline[0] = 0;
	strcat(newline, "netmask ");
	strcat(newline, tmp);
	free(intf_conf_lines[wlan_mask]);
	intf_conf_lines[wlan_mask] = newline;

	// save to file
	fp = fopen(NETIF_CONFIG_FILE, "w");
	for (i=0; i<MAX_LAN_CONF_LINES; i++) {
		if (intf_conf_lines[i] == NULL) {
			break;
		}
		fwrite(intf_conf_lines[i], strlen(intf_conf_lines[i]), 1, fp);
		fwrite("\n", 1, 1, fp);
	}
	fclose(fp);

	for (i=0; i<MAX_LAN_CONF_LINES; i++) {
		if (intf_conf_lines[i] == NULL) {
			break;
		}
		free(intf_conf_lines[i]);
	}

	return 0;
}


#if 0

int main()
{
	save_new_lan_config();

	return 0;
}
#endif


