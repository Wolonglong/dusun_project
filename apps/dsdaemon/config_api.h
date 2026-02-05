#ifndef __CONFIG_API__
#define __CONFIG_API__
int config_get(char* file, char *section, char *option, char *pdata, unsigned short *plen);
int config_set(char *file, char *section, char *option, char *pdata, unsigned short *plen);
int uci_get_str(char *arg, char *out);
int uci_set_str(char *arg);
int uci_del_str(char *arg);
int my_uci_commit(void);

#endif

