#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>

#include "shared_macros.h"
#include "config_api.h"

#define MAX_NETIF_CONF_LINES  50
static char* intf_conf_lines[MAX_NETIF_CONF_LINES];

static int read_intf_config()
{
	FILE *fp;
	char *line = NULL;
	int lines = 0;
	size_t len;
	ssize_t read;
	int found_eth0 = 0;

	memset(intf_conf_lines, 0, sizeof(intf_conf_lines));
	fp = fopen(NETIF_CONFIG_FILE, "r");
	while ((read = getline(&line, &len, fp)) > 0) {
		line[read-1]='\0';
		//printf("[line %d, len %ld] %s\n", lines, read, line);
		if (strncmp(line, "auto", 4) == 0) {
			if (strcmp(line, "auto eth0") == 0) {
				found_eth0 = 1; // skip eth0 config lines
			} else {
				found_eth0 = 0;
			}
		}
		if (found_eth0) 
			continue;  // skip eth0 config lines

		intf_conf_lines[lines] = strdup(line);
		lines++;
		if (lines >= MAX_NETIF_CONF_LINES) {
			exit(-1);
		}
	}
	if (line)
		free(line);
	fclose(fp);
	return 0;
}

static void free_all_lines()
{
	int i;
	for (i=0; i<MAX_NETIF_CONF_LINES; i++) {
		if (intf_conf_lines[i] == NULL) {
			break;
		}
		free(intf_conf_lines[i]);
	}
}

int save_apply_new_wan_config(int save2intf)
{
	char *newline;
	char tmp[100];
	unsigned short tmplen;
	int rc;
	int i;
	FILE *fp;
	char cmdline[256];
	int config_line_index = -1;
	int is_dhcp = 0;

	// ifconfig eth0 192.168.1.7 netmask 255.255.255.0
	// route add default gw 192.168.1.1

	cmdline[0] = 0;
	strcat(cmdline, "ifconfig eth0 ");

	read_intf_config();
	for (i=0; i<MAX_NETIF_CONF_LINES; i++) {
		if (intf_conf_lines[i] == NULL) {
			config_line_index = i;
			break;
		}
	}
	if (config_line_index < 0) {
		free_all_lines();
		return -1;
	}

	newline = malloc(256);
	newline[0] = 0;
	strcat(newline, "auto eth0");
	intf_conf_lines[config_line_index++] = newline;

	tmp[0] = 0;
	rc = config_get("network", "wan", "proto", tmp, &tmplen);
	printf("proto is %s --%d --%d\n", tmp,  tmplen, rc);
	if (rc !=0 ) {
		free_all_lines();
		return -1;
	}
	if (strcmp(tmp, "dhcp") == 0) {
		// good, it's DHCP
		newline = malloc(256);
		newline[0] = 0;
		strcat(newline, "iface eth0 inet dhcp");
		intf_conf_lines[config_line_index++] = newline;
		is_dhcp = 1;
		goto __save_to_netif; 
	}

	if (strcmp(tmp, "static") != 0) {
		free_all_lines();
		return -1;
	}

	newline = malloc(256);
	newline[0] = 0;
	strcat(newline, "iface eth0 inet static");
	intf_conf_lines[config_line_index++] = newline;

	tmp[0] = 0;
	rc = config_get("network", "wan", "ipaddr", tmp, &tmplen);
	printf("ipaddr is %s --%d --%d\n", tmp,  tmplen, rc);
	if (rc !=0 ) {
		free_all_lines();
		return -1;
	}
	if(isVaildIp(tmp) != 0)
	{
		syslog(LOG_ERR, "ipaddr error\n");
		free_all_lines();
		return -1;
	}
	newline = malloc(256);
	newline[0] = 0;
	strcat(newline, "address ");
	strcat(newline, tmp);
	intf_conf_lines[config_line_index++] = newline;
	strcat(cmdline, tmp);

	strcat(cmdline, " netmask ");
	tmp[0] = 0;
	rc = config_get("network", "wan", "netmask", tmp, &tmplen);
	printf("netmask is %s --%d --%d\n", tmp,  tmplen, rc);
	if (rc !=0 ) {
		free_all_lines();
		return -1;
	}
	if(isVaildIp(tmp) != 0)
	{
		syslog(LOG_ERR, "netmask error\n");
		free_all_lines();
		return -1;
	}
	newline = malloc(256);
	newline[0] = 0;
	strcat(newline, "netmask ");
	strcat(newline, tmp);
	intf_conf_lines[config_line_index++] = newline;
	strcat(cmdline, tmp);

	tmp[0] = 0;
	rc = config_get("network", "wan", "gateway", tmp, &tmplen);
	printf("gateway is %s --%d --%d\n", tmp,  tmplen, rc);
	if (rc !=0 ) {
		free_all_lines();
		return -1;
	}
	if(isVaildIp(tmp) != 0)
	{
		syslog(LOG_ERR, "gateway error\n");
		free_all_lines();
		return -1;
	}

	system("killall udhcpc");  // now start to set static IP config
	
	sleep(1);
	
	newline = malloc(256);
	newline[0] = 0;
	strcat(newline, "gateway ");
	strcat(newline, tmp);
	intf_conf_lines[config_line_index++] = newline;

	printf("%s\n", cmdline);
	system(cmdline); // set ip and netmask
	cmdline[0] = 0;
	strcat(cmdline, "route add default gw ");
	strcat(cmdline, tmp);
	printf("%s\n", cmdline);
	system(cmdline); // set gateway

__save_to_resolv_conf:
	tmp[0] = 0;
	rc = config_get("network", "wan", "dns", tmp, &tmplen);
	printf("dns is %s --%d --%d\n", tmp,  tmplen, rc);
	if (rc !=0 ) {
		free_all_lines();
		return -1;
	}
	
	cmdline[0] = 0;
	strcat(cmdline, "echo \"nameserver ");
	strcat(cmdline, tmp);
	strcat(cmdline, "  # eth0\" > /tmp/resolv.conf");
	printf("%s\n", cmdline);
	system(cmdline); // set dns

__save_to_netif:
	// save to file
	if (save2intf) {
		fp = fopen(NETIF_CONFIG_FILE, "w");
		for (i=0; i<MAX_NETIF_CONF_LINES; i++) {
			if (intf_conf_lines[i] == NULL) {
				break;
			}
			fwrite(intf_conf_lines[i], strlen(intf_conf_lines[i]), 1, fp);
			fwrite("\n", 1, 1, fp);
		}
		fclose(fp);
	}

	free_all_lines();

	if (is_dhcp) {
		system("cat /dev/null > /etc/resolv.conf");
		system("killall udhcpc");  // now restart udhcpc
		system("udhcpc -R -n -O search -p /var/run/udhcpc.eth0.pid -i eth0 -x hostname:DUSUN");

	}

	return 0;
}


int isVaildIp(const char *ip)
{
    int dots = 0; /*字符.的个数*/
    int setions = 0; /*ip每一部分总和（0-255）*/

    if (NULL == ip || *ip == '.') { /*排除输入参数为NULL, 或者一个字符为'.'的字符串*/
        return -1;
    }

    while (*ip) {

        if (*ip == '.') {
            dots ++;
            if (setions >= 0 && setions <= 255) { /*检查ip是否合法*/
                setions = 0;
                ip++;
                continue;
            }
            return -1;
        }
        else if (*ip >= '0' && *ip <= '9') { /*判断是不是数字*/
            setions = setions * 10 + (*ip - '0'); /*求每一段总和*/
        } else
            return -1;
        ip++;
    }
	/*判断IP最后一段是否合法*/
    if (setions >= 0 && setions <= 255) {
        if (dots == 3) {
            return 0;
        }
    }

    return -1;
}



#if 0

int main()
{
	return save_apply_new_wan_config();
}
#endif


