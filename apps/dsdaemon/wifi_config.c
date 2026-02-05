#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>

#include "shared_macros.h"
#include "config_api.h"

#define MAX_WIFI_CONF_LINES  200
static char* wifi_conf_lines[MAX_WIFI_CONF_LINES];

int read_wifi_default_config()
{
	FILE *fp;
	char *line = NULL;
	int lines = 0;
	size_t len;
	ssize_t read;

	memset(wifi_conf_lines, 0, sizeof(wifi_conf_lines));
	fp = fopen(DF_HOSTAPD_CONFIG_FILE, "r");
	while ((read = getline(&line, &len, fp)) > 0) {
		line[read-1]='\0';
		//printf("[line %d, len %ld] %s\n", lines, read, line);
		wifi_conf_lines[lines] = strdup(line);
		lines++;
		if (lines >= MAX_WIFI_CONF_LINES) {
			exit(-1);
		}
	}
	if (line)
		free(line);
	fclose(fp);
	return 0;
}

int save_new_wifi_config()
{
	char *newline;
	char tmp[100];
	unsigned short tmplen;
	int rc;
	int i,j;
	int channel;
	config_item_t items[] = {
		{NULL, "channel=", 8},
		{NULL, "hw_mode=", 8},
		{NULL, "wpa=", 4},
		{NULL, "ssid=", 5},
		{NULL, "wpa_passphrase=", 15},
	};

	//printf("\n\nGenerate new config:\n");

	tmp[0] = 0;
	rc = config_get("wireless", "radio0", "channel", tmp, &tmplen);
	//printf("channel is %s --%d --%d\n", tmp,  tmplen, rc);
	newline = malloc(256);
	newline[0] = 0;
	strcpy(newline, items[0].key);
	strcat(newline, tmp);
	channel = atoi(tmp);
	items[0].str = newline;

	newline = malloc(256);
	newline[0] = 0;
	strcpy(newline, items[1].key);
	if (channel < 36) {
		strcat(newline, "g");
	} else {
		strcat(newline, "a");
	}
	items[1].str = newline;

	tmp[0] = 0;
	rc = config_get("wireless", "ap", "encryption", tmp, &tmplen);
	//printf("encryption is %s --%d --%d\n", tmp,  tmplen, rc);
	newline = malloc(256);
	newline[0] = 0;
	strcpy(newline, items[2].key);
	if (strcmp(tmp, "none") == 0) {
		strcat(newline, "0");
	} else if (strcmp(tmp, "psk") == 0) {
		strcat(newline, "1");
	} else {
		strcat(newline, "2");
	}
	items[2].str = newline;

	tmp[0] = 0;
	rc = config_get("wireless", "ap", "ssid", tmp, &tmplen);
	//printf("ssid is %s --%d --%d\n", tmp,  tmplen, rc);
	newline = malloc(256);
	newline[0] = 0;
	strcpy(newline, items[3].key);
	strcat(newline, tmp);
	items[3].str = newline;

	tmp[0] = 0;
	rc = config_get("wireless", "ap", "key", tmp, &tmplen);
	//printf("key is %s --%d --%d\n", tmp,  tmplen, rc);
	newline = malloc(256);
	newline[0] = 0;
	strcpy(newline, items[4].key);
	strcat(newline, tmp);
	items[4].str = newline;

	for (i=0; i<MAX_WIFI_CONF_LINES; i++) {
		if (wifi_conf_lines[i] == NULL) {
			break;
		}
		for (j=0; j<sizeof(items)/sizeof(config_item_t); j++) {
			if (strncmp(wifi_conf_lines[i], items[j].key, items[j].key_len) == 0) {
				// replace with new value
				free(wifi_conf_lines[i]);
				wifi_conf_lines[i] = strdup(items[j].str);
				break;
			}
		}
	}

	for (j=0; j<sizeof(items)/sizeof(config_item_t); j++) {
		free(items[j].str);
	}

	// save to file
	{
	FILE *fp;

	fp = fopen(HOSTAPD_CONFIG_FILE, "w");
	for (i=0; i<MAX_WIFI_CONF_LINES; i++) {
		if (wifi_conf_lines[i] == NULL) {
			break;
		}
		fwrite(wifi_conf_lines[i], strlen(wifi_conf_lines[i]), 1, fp);
		fwrite("\n", 1, 1, fp);
	}
	fclose(fp);
	}
	return 0;
}


#if 0
// Unit test
void print_wifi_conf()
{
	int i;

	printf("\n\nDump config:\n", wifi_conf_lines[i]);
	for (i=0; i<MAX_WIFI_CONF_LINES; i++) {
		if (wifi_conf_lines[i] == NULL) {
			break;
		}
		printf("%s\n", wifi_conf_lines[i]);
	}
}

int main()
{
	read_default_config();
	print_wifi_conf();
	save_new_config();
	print_wifi_conf();

	return 0;
}
#endif


