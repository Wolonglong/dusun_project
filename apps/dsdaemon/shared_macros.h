#ifndef __DS_SHARED_MACROS__

#define  DF_HOSTAPD_CONFIG_FILE   "/ds/etc/hostapd.conf"
#define  DF_NETIF_CONFIG_FILE     "/ds/etc/network/interfaces"
#define  DF_DNSMASQ_CONFIG_FILE   "/ds/etc/dnsmasq.conf"

#define  HOSTAPD_CONFIG_FILE   "/etc/hostapd.conf"
#define  NETIF_CONFIG_FILE     "/etc/network/interfaces"
#define  DNSMASQ_CONFIG_FILE   "/etc/dnsmasq.conf"

typedef struct {
	char *str;
	char *key;
	int key_len;
} config_item_t;

#endif

