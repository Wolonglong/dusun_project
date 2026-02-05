#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/ioctl.h>

#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <limits.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/netlink.h>

#include "config_api.h"
#include "wifi_config.h"
#include "lan_config.h"
#include "wan_config.h"
#include "tb_config.h"

//#define TEST_UCI
//#define TRACE_DEBUG

#ifdef  TRACE_DEBUG
#define TRACE(A)   printf A
#else
#define TRACE(A)   
#endif

#define MAX_FDS  5
#define MAXLINE  1024
#define FIFO_FILE  "/tmp/dsgw_fifo"

#define MAX_PAYLOAD    101
#define NLMSG_LINK_STATUS_UP     0x11
#define NLMSG_LINK_STATUS_DOWN   0x13
#define NLMSG_GETPID           0x12
#define NETLINK_TEST   30

#define GPIONUM "gpio67"

// keep it same as kernel sdmmc_vendor_storage.c
struct rk_vendor_req {
	unsigned int tag;
	unsigned short id;
	unsigned short len;
	unsigned char data[1024];
};
#define VENDOR_REQ_TAG          0x56524551
#define VENDOR_READ_IO          _IOW('v', 0x01, unsigned int)
#define VENDOR_WRITE_IO         _IOW('v', 0x02, unsigned int)

// same as rk_vendor_storage.h
#define RSV_ID                          0
#define SN_ID                           1
#define WIFI_MAC_ID                     2
#define LAN_MAC_ID                      3
#define BT_MAC_ID                       4
#define HDCP_14_HDMI_ID                 5
#define HDCP_14_DP_ID                   6
#define HDCP_2X_ID                      7
#define DRM_KEY_ID                      8
#define PLAYREADY_CERT_ID               9
#define ATTENTION_KEY_ID                10
#define PLAYREADY_ROOT_KEY_0_ID         11
#define PLAYREADY_ROOT_KEY_1_ID         12
#define SENSOR_CALIBRATION_ID           13
#define IMEI_ID                         15
// end

#define REGION_ID   DRM_KEY_ID

int g_network_OK = 0;
int esw_fd;

// for system reset pin
int g_sysresetpin_pressed = 0;
int g_sysresetpin_press_cnt = 0;
int g_sysreset_timer_started = 0;
int g_restore_setting_timer_started = 0;
int g_restore_setting_triggerd = 0;
unsigned int g_networkcable_disconnect_cnt = 0;
unsigned int g_networkcable_connect_cnt = 0;
int lte_activate = 0;

void handle_reset(int signo);
void prepare_restore_setting(int signo);
void stop_all_services(void);
void network_bad_ind(void);
void network_good_ind(void);
void resetup_bg96_ifneeded(void);

void start_restore_setting_check_timer() 
{ 
	struct itimerval value;
	struct sigaction tact;

	tact.sa_handler = prepare_restore_setting; 
 	tact.sa_flags = 0; 
 	sigemptyset(&tact.sa_mask);
	sigaction(SIGALRM, &tact, NULL);

	value.it_value.tv_sec = 8;
	value.it_value.tv_usec = 0;
	value.it_interval = value.it_value;
	setitimer(ITIMER_REAL, &value, NULL);
	g_restore_setting_timer_started = 1;
}

void cancel_restore_setting_check_timer() 
{ 
	struct itimerval value;
	value.it_value.tv_sec = 0;
	value.it_value.tv_usec = 0;
	value.it_interval = value.it_value;
	setitimer(ITIMER_REAL, &value, NULL);
	g_restore_setting_timer_started = 0;
}

void start_resetcheck_timer() 
{ 
	struct itimerval value;
	struct sigaction tact;

	tact.sa_handler = handle_reset; 
 	tact.sa_flags = 0; 
 	sigemptyset(&tact.sa_mask);
	sigaction(SIGALRM, &tact, NULL);

	value.it_value.tv_sec = 2;
	value.it_value.tv_usec = 0;
	value.it_interval = value.it_value;
	setitimer(ITIMER_REAL, &value, NULL);
	g_sysreset_timer_started = 1;
}

void cancel_resetcheck_timer() 
{ 
	struct itimerval value;
	value.it_value.tv_sec = 0;
	value.it_value.tv_usec = 0;
	value.it_interval = value.it_value;
	setitimer(ITIMER_REAL, &value, NULL);
	g_sysreset_timer_started = 0;
}

void prepare_restore_setting(int signo) 
{ 
	syslog(LOG_INFO, "10 secs now, prepare_restore_setting\n");
	TRACE(("10 secs now, prepare_restore_setting\n"));
	system("killall dsled; /usr/bin/dsled g blink_fast");
	g_restore_setting_triggerd = 1;
}

void handle_reset(int signo)
{
	if (g_sysresetpin_press_cnt == 2) {
		syslog(LOG_INFO, "Do system reset\n");
		TRACE(("Do system reset\n"));
		system("killall dsled; /usr/bin/dsled r on");
		usleep(10000);
	        system("cut_off_battery.sh");
		sleep(1);
	} else if (g_sysresetpin_press_cnt >= 3) {
		syslog(LOG_INFO, "Do system update reset\n");
		TRACE(("Do system update reset\n"));
		system("killall dsled; /usr/bin/dsled r on");
		stop_all_services();
		usleep(10000);
		system("/usr/bin/bootm2recovery.sh");
		while(1) {sleep(10000);}
	} else if (g_sysresetpin_press_cnt == 0){
		syslog(LOG_INFO, "2 secs timeout, restore setting?\n");
		TRACE(("2 secs timeout, restore setting?\n"));
		cancel_resetcheck_timer();
		start_restore_setting_check_timer();
		return;
	} else {
		syslog(LOG_INFO, "2 secs timeout, ignore %d press cnt\n", g_sysresetpin_press_cnt);
		TRACE(("2 secs timeout, ignore %d press cnt\n", g_sysresetpin_press_cnt));
	}

	cancel_resetcheck_timer();
	g_sysresetpin_press_cnt = 0;
}

static void err_quit(const char *fmt, ...)
{
        va_list args;
        char buf[MAXLINE];

        va_start(args, fmt);
        vsnprintf(buf, MAXLINE-1, fmt, args);
        va_end(args);
        syslog(LOG_ERR, "%s", buf);
        exit(-1);
}

static void daemonize(const char *cmd)
{
	int i, fd0, fd1, fd2;
	pid_t pid;
	struct rlimit rl;
	struct sigaction sa;

	/* * Clear file creation mask. */
	umask(0);
	
	/* * Get maximum number of file descriptors. */
	if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
		err_quit("%s: can't get file limit\n", cmd);
	
	/* * Become a session leader to lose controlling TTY. */
	if ((pid = fork()) < 0)
		err_quit("%s: can't fork\n", cmd);
	else if (pid != 0) /* parent */
		exit(0);
	setsid();

	/* * Ensure future opens won't allocate controlling TTYs. */
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGHUP, &sa, NULL) < 0)
		err_quit("%s: can't ignore SIGHUP\n", cmd);
	if ((pid = fork()) < 0)
		err_quit("%s: can't fork\n", cmd);
	else if (pid != 0) /* parent */
		exit(0);
	
	/* * Change the current working directory to the root so * we won't prevent file systems from being unmounted. */
	if (chdir("/") < 0)
		err_quit("%s: can't change directory to /\n", cmd);
	
	/* * Close all open file descriptors. */
	if (rl.rlim_max == RLIM_INFINITY)
		rl.rlim_max = 1024;
	for (i = 0; i < rl.rlim_max; i++)
		close(i);
	
	/* * Attach file descriptors 0, 1, and 2 to /dev/null. */
	fd0 = open("/dev/null", O_RDWR);
	fd1 = dup(0);
	fd2 = dup(0);
	
	if (fd0 != 0 || fd1 != 1 || fd2 != 2) {
		syslog(LOG_ERR, "unexpected file descriptors %d %d %d",fd0, fd1, fd2);
		exit(1);
	}
}


int init_netlink()
{
	struct sockaddr_nl src_addr, dst_addr;
	int sockfd;
	struct nlmsghdr *nlh = NULL;
	int ret;

	sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_TEST);
	bzero(&src_addr, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = 0; // no group
	ret=bind(sockfd, (struct sockaddr*)&src_addr, sizeof(src_addr));
	syslog(LOG_INFO, "Bind Netlink sock ret %d\n", ret);

	if (sockfd < 0)
		return sockfd;

	bzero(&dst_addr, sizeof(dst_addr));
	dst_addr.nl_family = AF_NETLINK;
	dst_addr.nl_pid = 0;  // send to kernel
	dst_addr.nl_groups = 0;

	nlh = malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlh, 0, sizeof(struct nlmsghdr));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = src_addr.nl_pid;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type = NLMSG_GETPID;
	strcpy(NLMSG_DATA(nlh), "Give Pid");
	ret = sendto(sockfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&dst_addr, sizeof(struct sockaddr_nl));
	if (ret < 0)
		syslog(LOG_ERR, "sendmsg failed: %s\n", strerror(errno));
	free(nlh);

	return sockfd;
}


int handle_fifo_event(int fd)
{
#define BUFFER_SIZE  64
	int state;
	int res;
	char buffer[BUFFER_SIZE];
	int bytes = 0;

	do {
		res  = read (fd, &buffer[bytes], BUFFER_SIZE-bytes);
		TRACE(("read res=%d\n", res));
		if (res > 0)
 			bytes  += res;
	} while (res  >  0);  
	
	buffer[bytes] = 0;
	syslog(LOG_INFO, "%d bytes read from fifo, res=%d, %s\n", bytes, res, buffer);
	if (strcmp(buffer, "wifi") == 0) {
		syslog(LOG_INFO, "Restart wifi\n");
		save_new_wifi_config();
		system("/usr/bin/ds_conf_ap.sh");
	} else if (strcmp(buffer, "lan") == 0) {
		syslog(LOG_INFO, "Restart LAN\n");
		save_new_lan_config();
		system("/usr/bin/ds_conf_ap.sh");
	} else if (strcmp(buffer, "wan") == 0) {
		syslog(LOG_INFO, "Restart WAN\n");
		save_apply_new_wan_config(1);
	} else if (strcmp(buffer, "bg96") == 0) {
		syslog(LOG_INFO, "Restart BG96 if needed\n");
		resetup_bg96_ifneeded();
	} else if (strcmp(buffer, "mqtt") == 0) {
		syslog(LOG_INFO, "Restart thingsboard\n");
		save_apply_thingsboard();
		system("killall -9 python3");
	} else if (bytes > 0) {
		syslog(LOG_ERR, "%s, unknown message!\n", buffer);
	}

	if (res == 0)  // writer close fifo  
		return -1;

	return 0;
}

static void waitfor_system_ready()
{
	FILE *fp;
	char line[1024];
	int cnt = 0;

	while (1) {
		fp = popen("ifconfig | grep wlan0", "r");
		while (fgets(line, sizeof(line), fp)) {
			if (strstr(line, "wlan0")) {
				pclose(fp);
				goto __out;
			}
		}
		pclose(fp);
		sleep(1);
		cnt++;
		if (cnt > 30) {
			syslog(LOG_ERR, "Wait for wlan0 up timeout!");
			break;
		}
	}
__out:
	syslog(LOG_INFO, "wlan0 is up!");
}


static void kill_bg96()
{
	FILE *fp;
	char line[1024];
	int found = 0;
	char killcmd[64];
	char *tmp;

	fp = popen("ps -x | grep bg96_dial", "r");
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "bg96_dial.sh")) {
			found = 1;
			killcmd[0] = 0;
			strcat(killcmd, "kill -9 ");
			tmp = line;           // e.g.        650 root     {exe} ash /usr/bin/bg96_dial.sh
			while(*tmp == ' ') tmp++;
			while(*tmp != ' ') tmp++;
			*tmp = 0;
			strcat(killcmd, line);
			syslog(LOG_INFO, "Kill bg96_dial.sh %s!", killcmd);
			system(killcmd);
		}
	}
	pclose(fp);

	system("killall pppd");
	sleep(1);
	system("/usr/bin/bg96_powerup.sh off");
}

static void setup_wan()
{
	FILE *fp;
	char line[1024];
	int found = 0;

	network_bad_ind();
	fp = popen("ifconfig eth0 | grep RUNNING", "r");
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "RUNNING")) {
			found = 1;
			break;
		}
	}
	pclose(fp);

	syslog(LOG_INFO, "eth0 link is %s!", found?"UP":"DOWN");
	if (found) { // means eth link is UP
		kill_bg96();
		system("killall udhcpc");
		usleep(3000);
		system("cat /dev/null > /etc/resolv.conf");
		system("udhcpc -R -n -O search -p /var/run/udhcpc.eth0.pid -i eth0");
	} else {
		system("ifconfig eth0 0.0.0.0");
		kill_bg96();
		usleep(3000);
		system("cat /dev/null > /etc/resolv.conf");
		system("/usr/bin/dswrapper bg96");  // restart bg96
	}
}

void resetup_bg96_ifneeded()
{
	FILE *fp;
	char line[1024];
	int found = 0;

	network_bad_ind();
	fp = popen("ifconfig eth0 | grep RUNNING", "r");
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "RUNNING")) {
			found = 1;
			break;
		}
	}
	pclose(fp);

	if (found) { // means eth link is UP
		syslog(LOG_INFO, "eth0 link is UP, do nothing");
	} else {
		syslog(LOG_INFO, "eth0 link is DOWN, restart LTE");
		kill_bg96();
		usleep(3000);
		system("cat /dev/null > /etc/resolv.conf");
		system("bg96_dial.sh &");  // restart bg96
	}
}

void stop_all_services(void)
{
	FILE *fp;
	char line[2048];
	int found = 0;
	char killcmd[64];
	char *tmp;

	system("ifconfig eth0 down");
	system("killall  udhcpc");
	kill_bg96();
	system("killall hostapd");
	system("/etc/init.d/S80dnsmasq stop");

	// TODO
}

static void nl_fd_handler(int sock)
{
	typedef struct _user_msg_info
	{
		struct nlmsghdr hdr;
		char  msg[MAX_PAYLOAD];
	} user_msg_info;
	user_msg_info  u_info;
	int ret;
	socklen_t len;
	struct sockaddr_nl daddr;

	memset(&daddr, 0, sizeof(daddr));
	daddr.nl_family = AF_NETLINK;
	daddr.nl_pid = 0; // kernel
	daddr.nl_groups = 0;

	memset(&u_info, 0, sizeof(u_info));
	len = sizeof(struct sockaddr_nl);
	ret = recvfrom(sock, &u_info, sizeof(user_msg_info), 0, (struct sockaddr *)&daddr, &len);
	if (ret < 0) {
		syslog(LOG_ERR, "recv form kernel error\n");
	} else {
		syslog(LOG_INFO, "Received link-status change message payload: %s\n", u_info.msg);
		setup_wan();
	}
}

void network_bad_ind()
{
	if (g_network_OK) {
		system("killall dsled; /usr/bin/dsled r breathe");
	}
	g_network_OK = 0;
}

void network_good_ind()
{
	struct ifreq ifr;
	struct sockaddr_in *sin;

	if (g_network_OK == 0) {
		memset(&ifr, 0, sizeof(ifr));
		strcpy(ifr.ifr_name, "ppp0");
		if (ioctl(esw_fd, SIOCGIFFLAGS, &ifr) < 0) {
			syslog(LOG_INFO, "Get ppp0 flag failed, no ppp0?\n");
			// must be eth0 good
			system("killall dsled; /usr/bin/dsled b on");
		} else {
			system("killall dsled; /usr/bin/dsled g on");
		}
	}
	g_network_OK = 1;
}

int check_udhcpc()
{

	char line[1024];
	int found = 0;
	char tmp[100] = {0};
	int tmplen = 0;
	found = 0;
	if (access("/var/run/udhcpc.eth0.pid", 0) ==0) {
		found = 1;
	}

	if (!found) {
		if (config_get("network", "wan", "proto", tmp, &tmplen) != 0) {
			return 0;
		}
		if(strcmp(tmp,"dhcp") == 0)
		{
			syslog(LOG_INFO, "udhcpc not running!");
			system("udhcpc -R -n -O search -p /var/run/udhcpc.eth0.pid -i eth0 -x hostname:DUSUN");
			return 0;
		}

	}
	return 0;
}

int check_eth0_carrier()
{
	int skfd, eth0_ret;
	char buf[2];
	if (access("/etc/init.d/S99lte", 0) ==0) {
	skfd= open("/sys/class/net/eth0/carrier", O_RDONLY);
	if (skfd < 0) {
		err_quit(" can't open carrier skfd=%d\n",skfd);
		return 0;
	}
	
	int val;
	int ret = lseek(skfd, 0, SEEK_SET);

	if (ret >= 0){
	     ret = read(skfd, buf, 2);
	     val = buf[0]-'0';
		if (val == 0) {
			g_networkcable_disconnect_cnt ++;
			g_networkcable_connect_cnt = 0;
			syslog(LOG_INFO, "Network cable disconnected,g_networkcable_disconnect_cnt =%d\n",g_networkcable_disconnect_cnt);
			if(g_networkcable_disconnect_cnt > 5 && lte_activate == 0){
			syslog(LOG_INFO, "bg96_up!!!\n");
			kill_bg96();
			usleep(3000);
			system("bg96_dial.sh &");
			lte_activate = 1;
		}
		} else if (val == 1) {
			g_networkcable_disconnect_cnt = 0;
			g_networkcable_connect_cnt ++;
			syslog(LOG_INFO, "Network cable connected\n");
			if(g_networkcable_connect_cnt > 5 && lte_activate == 1){
				syslog(LOG_INFO, "kill bg96!!!\n");
				kill_bg96();
				system("route del default");
				network_bad_ind();
				system("/etc/init.d/networking  restart");
				lte_activate = 0;
			}
		}
	}
	close(skfd);
	}
}


int check_wwan_broken()
{
	FILE *fp;
	char line[1024];
	int found = 0;

	found = 0;
	fp = popen("ping -c 1 www.baidu.com", "r");
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, " 0% packet loss")) {
			syslog(LOG_INFO, "Ping GW OK!");
			found = 1;
			break;
		}
	}
	pclose(fp);
	if (!found) {
		syslog(LOG_ERR, "Ping baidu failure!");
		network_bad_ind();
		check_udhcpc();
		return 1;
	} else {
		/* reset count */
		network_good_ind();
		return 0;
	}
}


int check_bul()
{
	FILE *fp;
	char line[1024];
	int found = 0;

	found = 0;
	fp = popen("ps | grep bul", "r");
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "/usr/bin/bul -d /dev/ttyUSB0")) {
			syslog(LOG_INFO, "bul is run!");
			found = 1;
			break;
		}
	}
	pclose(fp);
	if (!found) {
		syslog(LOG_INFO, "bul not running!");
		system("/usr/bin/bul -d /dev/ttyUSB0 -b115200 > /dev/null&");
		return 0;
	}
}

int check_zigbee()
{
	FILE *fp;
	char line[1024];
	int found = 0;

	found = 0;
	fp = popen("ps | grep AmberGwZ3", "r");
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "AmberGwZ3 -n1 -p/dev/ttyUSB1")) {
			syslog(LOG_INFO, "zigbee is run!");
			found = 1;
			break;
		}
	}
	pclose(fp);
	if (!found) {
		syslog(LOG_INFO, "zigbee not running!");
		system("AmberGwZ3 -n1 -p/dev/ttyUSB1 -b115200 -d > /dev/null &");
		return 0;
	}

}

int check_zwave()
{
	FILE *fp;
	char line[1024];
	int found = 0;

	found = 0;
	fp = popen("ps | grep zwdevd", "r");
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "zwdevd -b115200 -d/dev/ttyS1")) {
			syslog(LOG_INFO, "zwdev  is run!");
			found = 1;
			break;
		}
	}
	pclose(fp);
	if (!found) {
		syslog(LOG_INFO, "zwdev not running!");
		system("zwdevd -b115200 -d/dev/ttyS1 > /dev/null &");
		return 0;
	}

}


int check_thingsboard()
{
	FILE *fp;
	char line[1024];
	int found = 0;

	found = 0;
	fp = popen("ps | grep tb_gateway", "r");
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "thingsboard_gateway/tb_gateway.py")) {
			syslog(LOG_INFO, "tb_gateway  is run!");
			found = 1;
			break;
		}
	}
	pclose(fp);
	if (!found) {
		syslog(LOG_INFO, "tb_gateway not running!");
		system("python3 /root/thingsboard-gateway-2.7/thingsboard_gateway/tb_gateway.py >> /tmp/python.log &");
		return 0;
	}

}


static int re_calc_maxfd(int fds[], int fds_cnt)
{
	int fd_max = 0;
	int i;

	for (i=0; i<fds_cnt; i++) {
		if (fds[i] > fd_max)
			fd_max = fds[i];
	}

	return fd_max;
}

int vendor_storage_mac_read_set(int set)
{
	int ret;
	int sys_fd;
	char cmd[128];

	struct rk_vendor_req req;
	sys_fd = open("/dev/vendor_storage", O_RDWR, 0);
	if (sys_fd < 0) {
		printf("vendor_storage open error\n");
		return -1;
	}
	req.tag = VENDOR_REQ_TAG;
	req.id = LAN_MAC_ID;
	req.len = 512;
	ret = ioctl(sys_fd, VENDOR_READ_IO, &req);
	if (ret) {
		printf("vendor_storage read error\n");
	} else {
		unsigned char *tmp = (unsigned char *)&req;
		int len;
		cmd[0];
		if ((tmp[8] & 0x1) || (tmp[8] == 0 && tmp[9] == 0 && tmp[10] ==0 
				&& tmp[11] == 0 && tmp[12] == 0 && tmp[13] == 0)) {
			printf("Invalid MAC address %02x:%02x:%02x:%02x:%02x:%02x\n",
					tmp[8], tmp[9], tmp[10], tmp[11], tmp[12], tmp[13]);	
			syslog(LOG_ERR, "Invalid MAC address %02x:%02x:%02x:%02x:%02x:%02x",
					tmp[8], tmp[9], tmp[10], tmp[11], tmp[12], tmp[13]);	
			goto __out;	
		}

		if (set) {
		strcpy(cmd, "ifconfig eth0 hw ether ");
		len = strlen(cmd);
		sprintf(&cmd[len], "%02x:%02x:%02x:%02x:%02x:%02x",
			tmp[8], tmp[9], tmp[10], tmp[11], tmp[12], tmp[13]);
			printf("%s", cmd);
		system("ifconfig eth0 down");
		system(cmd);
		system("ifconfig eth0 up");
		} else {
			printf("Curr MAC address %02x:%02x:%02x:%02x:%02x:%02x\n",
				tmp[8], tmp[9], tmp[10], tmp[11], tmp[12], tmp[13]);
		}
	}

__out:
	close(sys_fd);
	return ret;
}


/* Below for MAC address set */

#define ETHER_ADDR_LEN          6

/*
* Structure of a 48-bit Ethernet address.
*/
struct  ether_addr {
	unsigned char octet[ETHER_ADDR_LEN];
};


static inline int
xdigit (char c) {
    unsigned d;
    d = (unsigned)(c-'0');
    if (d < 10) return (int)d;
    d = (unsigned)(c-'a');
    if (d < 6) return (int)(10+d);
    d = (unsigned)(c-'A');
    if (d < 6) return (int)(10+d);
    return -1;
}
/*
 * Convert Ethernet address in the standard hex-digits-and-colons to binary
 * representation.
 * Re-entrant version (GNU extensions)
 */
struct ether_addr *
ether_aton_r (const char *asc, struct ether_addr * addr)
{
    int i, val0, val1;
    for (i = 0; i < ETHER_ADDR_LEN; ++i) {
        val0 = xdigit(*asc);
        asc++;
        if (val0 < 0)
            return NULL;
        val1 = xdigit(*asc);
        asc++;
        if (val1 < 0)
            return NULL;
        addr->octet[i] = (u_int8_t)((val0 << 4) + val1);
        if (i < ETHER_ADDR_LEN - 1) {
            if (*asc != ':')
                return NULL;
            asc++;
        }
    }
    if (*asc != '\0')
        return NULL;
    return addr;
}


int vendor_storage_mac_write(const char *mac_str)
{
	int ret;
	int sys_fd;
	struct ether_addr mac_addr;
	struct rk_vendor_req req;

	if (ether_aton_r(mac_str, &mac_addr) == NULL) {
		printf("Wrong MAC addr string: %s\n", mac_str);
		return -1;
	}

	sys_fd = open("/dev/vendor_storage", O_RDWR, 0);
	if (sys_fd < 0) {
		printf("vendor_storage open error\n");
		return -1;
	}
	req.tag = VENDOR_REQ_TAG;
	req.id = LAN_MAC_ID;
	memcpy(req.data, mac_addr.octet, ETHER_ADDR_LEN);
	req.len = ETHER_ADDR_LEN;
	ret = ioctl(sys_fd, VENDOR_WRITE_IO, &req);
	if (ret) {
		printf("vendor_storage set error\n");
	}

	close(sys_fd);
	return ret;
}
/* end of MAC setting code */
int vendor_storage_region_write(const char *region_str)
{
	int ret;
	int sys_fd;
	struct rk_vendor_req req;

	// TODO, sanity check region string

	sys_fd = open("/dev/vendor_storage", O_RDWR, 0);
	if (sys_fd < 0) {
		printf("vendor_storage open error\n");
		return -1;
	}
	req.tag = VENDOR_REQ_TAG;
	req.id = REGION_ID;
	strcpy(req.data, region_str);
	req.len = strlen(region_str);
	ret = ioctl(sys_fd, VENDOR_WRITE_IO, &req);
	if (ret) {
		printf("vendor_storage set error\n");
	}

	close(sys_fd);
	return ret;
}
int vendor_storage_region_read(void)
{
	int ret;
	int sys_fd;

	struct rk_vendor_req req;
	sys_fd = open("/dev/vendor_storage", O_RDWR, 0);
	if (sys_fd < 0) {
		printf("vendor_storage open error\n");
		return -1;
	}
	req.tag = VENDOR_REQ_TAG;
	req.id = REGION_ID;
	req.len = 512;
	ret = ioctl(sys_fd, VENDOR_READ_IO, &req);
	if (ret) {
		printf("vendor_storage read error\n");
	} else {
		unsigned char *tmp = (unsigned char *)&req;
		printf("Region code is: %s\n", &tmp[8]);
	}
	close(sys_fd);
	return ret;
}


void cut_down_battery_output(void)
{
	system("/usr/bin/cut_off_battery.sh");
}

int cut_down_battery_if_needed(void)
{
	FILE * fp;
	char buf[1024];
	size_t len = 0;
	ssize_t read;
	int capacity;
	int vol;
	char *line = buf;

	fp = fopen("/sys/class/power_supply/bq27546-0/status", "r");
	if (fp == NULL) {
		syslog(LOG_ERR, "line %d: Open bq27546 file failed!", __LINE__);
		return -1;
	}
	read = getline(&line, &len, fp);
	if (read <= 0) {
		syslog(LOG_ERR, "line %d: Read bq27546 file failed!", __LINE__);
		fclose(fp);
		return -1;
	}
	fclose(fp);
	syslog(LOG_INFO, "Battery status %s\n", line);
	if (strncmp(line, "Discharging", 11) != 0) {
		//syslog(LOG_INFO, "Not Discharging: %s, return\n", line);
		return 0;
	}

	fp = fopen("/sys/class/power_supply/bq27546-0/current_now", "r");
	if (fp == NULL) {
		syslog(LOG_ERR, "line %d: Open bq27546 file failed!", __LINE__);
		return -1;
	}
	read = getline(&line, &len, fp);
	if (read <= 0) {
		syslog(LOG_ERR, "line %d: Read bq27546 file failed!", __LINE__);
		fclose(fp);
		return -1;
	}
	syslog(LOG_INFO, "Battery current_now %s\n", line);
	fclose(fp);
	if (line[0] != '-') { /* double confirm battery is Discharging*/
		//syslog(LOG_INFO, "Not Discharging: %s, return\n", line);
		return 0;
	}

	fp = fopen("/sys/class/power_supply/bq27546-0/capacity", "r");
	if (fp == NULL) {
		syslog(LOG_ERR, "line %d: Open bq27546 file failed!", __LINE__);
		return -1;
	}
	read = getline(&line, &len, fp);
	if (read <= 0) {
		syslog(LOG_ERR, "line %d: Read bq27546 file failed!", __LINE__);
		fclose(fp);
		return -1;
	}
	fclose(fp);

	capacity = atoi(line);
	syslog(LOG_INFO, "Battery capacity %d\n", capacity);
	if (capacity < 10) {
		syslog(LOG_ERR, "Lower Battery Power, cut off battery power output!");
		cut_down_battery_output();
	}

	fp = fopen("/sys/class/power_supply/bq27546-0/voltage_now", "r");
	if (fp == NULL) {
		syslog(LOG_ERR, "line %d: Open bq27546 file failed!", __LINE__);
		return -1;
	}
	read = getline(&line, &len, fp);
	if (read <= 0) {
		syslog(LOG_ERR, "line %d: Read bq27546 file failed!", __LINE__);
		fclose(fp);
		return -1;
	}
	fclose(fp);

	vol = atoi(line);
	syslog(LOG_INFO, "Battery voltage %d\n", vol);
	if (vol> 3000000 && vol < 3230000) {  // voltage must be a reasonable value
		syslog(LOG_ERR, "Lower Battery voltage, cut off battery power output!");
		cut_down_battery_output();
	}
	return 0;
}


#ifdef TEST_UCI
int test_uci(void)
{
	char tmp[100];
	unsigned short tmplen;
	int rc;

	tmp[0] = 0;
	rc = config_get("wireless", "radio0", "country", tmp, &tmplen);
	printf("country is %s --%d --%d\n", tmp,  tmplen, rc);

	tmp[0] = 0;
	rc = config_set("wireless", "radio0", "country", "US", &tmplen);
	printf("set country to 'US' --%d --%d\n", tmplen, rc);
	my_uci_commit();

	tmp[0] = 0;
	rc = config_get("wireless", "radio0", "country", tmp, &tmplen);
	printf("Now country is %s --%d --%d\n", tmp,  tmplen, rc);

	tmp[0] = 0;
	rc = config_get("wireless", "ap", "mode", tmp, &tmplen);
	printf("mode is %s --%d --%d\n", tmp, tmplen, rc);
}
#endif

int main(int argc, char * argv[])
{
	int ret;
	int i;
	int pipe_fd;
	int nlsk_fd;
	int sys_reset_gpio_pin;
	fd_set rset;
	int fd_max = 0;
	int fds[MAX_FDS];
	int fds_cnt = 0;
	fd_set eset;
	int round=0;
	struct timeval tv;

#ifdef TEST_UCI
	test_uci();
	return 0;
#endif
	
	if (argc == 2) {
		ret = -1;
		if (strcmp(argv[0], "ds_sethwmac") == 0) {
			ret = vendor_storage_mac_write(argv[1]);
		} else if (strcmp(argv[0], "ds_region") == 0) {
			ret = vendor_storage_region_write(argv[1]);
		} else if (strcmp(argv[1], "-setmac") == 0) {
			return vendor_storage_mac_read_set(1);
		} else {
			printf("Unknown command\n");
		}
		return ret;
	}

	if (strcmp(argv[0], "ds_region") == 0) {
		vendor_storage_region_read();
		return 0;
	} else if (strcmp(argv[0], "ds_sethwmac") == 0) {
		return vendor_storage_mac_read_set(0);
	}

	openlog(argv[0], LOG_CONS, LOG_DAEMON);

	//cut_down_battery_if_needed();

#ifndef TRACE_DEBUG
	daemonize(argv[0]);
#endif

	// read default config
	read_wifi_default_config();

	esw_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (esw_fd < 0) {
		syslog(LOG_ERR, "%s create esw socket failed!", argv[0]);
		exit(0);
	}

	TRACE(("%s %d trace.\n", __FUNCTION__, __LINE__));

	if (access(FIFO_FILE, F_OK) ==0) {
		syslog(LOG_INFO, "%s exists, I'm not the 1st time start!\n", FIFO_FILE);
	} else {
		syslog(LOG_INFO, "%s not exists, create it.\n", FIFO_FILE);
		ret = mkfifo(FIFO_FILE, 0666);
		if (ret < 0) {
			err_quit("%s: Create %s failed! exit()\n", argv[0], FIFO_FILE);
		}
	}

	system("/usr/bin/export_zigbee_zwave_ble_gpio.sh");  // config GPIO
	//setenv("PYTHONPATH", "/root/thingsboard-gateway-2.7", 1);

	system("ubusaddobj &"); 
	/* now we can start services */
	waitfor_system_ready();
#ifndef TRACE_DEBUG
	system("/usr/bin/ds_conf_ap.sh");  // restart AP
#endif

	// first ping
	if (check_wwan_broken()) {
		setup_wan();
	}

	// create pipe	
	pipe_fd = open (FIFO_FILE, O_RDONLY|O_NONBLOCK);
	if (pipe_fd < 0) {
		err_quit("%s: can't open fifo %s\n", argv[0], FIFO_FILE);
	}

	// create netlink socket
	do {
		nlsk_fd = init_netlink();
		if (nlsk_fd < 0) {
			//close(pipe_fd);
			//close(sys_reset_gpio_pin);
			//err_quit("%s: Create netlink socket failed! exit()\n", argv[0]);
	                syslog(LOG_INFO, "netlink scoket failed");
			sleep(1);
	                syslog(LOG_INFO, "netlink scoket failed sleep");
		}
	}while(nlsk_fd < 0);

	// create gpio (system reset pin), always put this to last of fds
	sys_reset_gpio_pin = open("/sys/class/gpio/"GPIONUM"/value", O_RDONLY);
	if (sys_reset_gpio_pin < 0) {
		close(pipe_fd);
		err_quit("%s: can't open system reset pin GPIO file\n", argv[0]);
	}

	while (1) {
		round++;
		//syslog(LOG_INFO, "%s heart beat, round = 0x%x!\n", argv[0], round);
		TRACE(("%s heart beat!, round = 0x%x\n", argv[0], round));

		FD_ZERO(&rset);
		FD_ZERO(&eset);
		FD_SET(pipe_fd, &rset);
		fds[0] = pipe_fd;
		FD_SET(nlsk_fd, &rset);
		fds[1] = nlsk_fd;
		FD_SET(sys_reset_gpio_pin, &eset);
		fds[2] = sys_reset_gpio_pin;
		fds_cnt = 3;
		fd_max = re_calc_maxfd(fds, fds_cnt);

		tv.tv_sec = 5;
		tv.tv_usec = 0;
		ret = select(fd_max+1, &rset, NULL, &eset, &tv);
		if (ret < 0)
			continue;

		if (ret == 0) {
			//timeout happen
			//cut_down_battery_if_needed();
			check_wwan_broken();
			check_eth0_carrier();
			continue;
		}

		if (FD_ISSET(pipe_fd, &rset)) {
			int cmd;
			if ((cmd = handle_fifo_event(pipe_fd)) == -1) {
				FD_CLR(pipe_fd, &rset);
				close(pipe_fd);
				TRACE(("%s %d trace. close fd %d\n", __FUNCTION__, __LINE__, pipe_fd));
				pipe_fd = open (FIFO_FILE, O_RDONLY|O_NONBLOCK);
					if (pipe_fd < 0) {
					err_quit("%s: can't open fifo %s\n", argv[0], FIFO_FILE);
				}
				TRACE(("%s %d trace. new fd %d create\n", __FUNCTION__, __LINE__, pipe_fd));
			}
		}

		if (FD_ISSET(nlsk_fd, &rset)) {
			nl_fd_handler(nlsk_fd);
		}

		if (FD_ISSET(sys_reset_gpio_pin, &eset)) {
			/* get value */
			char buf[2];
			int ret = lseek(sys_reset_gpio_pin, 0, SEEK_SET);
			int val;

			if (ret >= 0) {
				ret = read(sys_reset_gpio_pin, buf, 2);
				buf[1] = '\0';
				if (ret == 2) {
					val = buf[0]-'0';
					syslog(LOG_INFO, "Read system reset pin ret = %d, value = %x\n", ret, val);
					//TRACE(("Read system reset pin ret = %d, value = %x\n", ret, val));
					if (val == 0) {
						g_sysresetpin_pressed = 1;
						if (g_sysreset_timer_started == 0) {
							// start timer
							syslog(LOG_INFO, "start_resetcheck_timer\n");
							TRACE(("start_resetcheck_timer\n"));
							start_resetcheck_timer();
						}
					} else if (val == 1) {
						if (g_sysresetpin_pressed == 1) {
							// released
							g_sysresetpin_press_cnt++;
							if (g_restore_setting_triggerd) {
								syslog(LOG_INFO, "Do restore setting reset\n");
								TRACE(("Do restore setting reset\n"));
								g_sysresetpin_press_cnt = 0;
								// we should never return
								stop_all_services();
								usleep(10000);
								system("killall -9 AmberGwZ3");
								system("rm -rf /f/*");  /* clean all configs in /f */
								system("cp /etc/backconfig/config/*  /etc/config/ ");  
								system("cp /etc/backconfig/shadow  /etc/shadow");
								system("cp /etc/backconfig/interfaces /etc/network");
								system("cp /etc/backconfig/hostname /etc/hostname");
								system("cp /etc/backconfig/hostapd.confback /etc/hostapd.conf");
								system("cp /etc/backconfig/wpa_supplicant.conf /etc/wpa_supplicant.conf");
								system("cp /etc/backconfig/dnsmasq.conf /etc/dnsmasq.conf");
 								system("cp /etc/backconfig/tb_gateway.yaml /root/thingsboard-gateway-2.7/thingsboard_gateway/config/tb_gateway.yaml ");
								system("cp /etc/backconfig/quectel* /etc/ppp/peers/ ");					
								system("echo GMT0 > /etc/TZ");
								system("ln -sf /usr/share/zoneinfo/GMT0  /etc/localtime");
								system("docker_reset.sh");
								system("sync ");
								usleep(10000);
								while(1) {
									system("reboot");
									sleep(1);
								}

								g_sysresetpin_press_cnt = 0;
								g_restore_setting_triggerd = 0;
								cancel_resetcheck_timer();
								cancel_restore_setting_check_timer();
							} else if (g_restore_setting_timer_started) {
								syslog(LOG_INFO, "Cancel restore setting timer\n");
								TRACE(("Cancel restore setting timer\n"));
								g_sysresetpin_press_cnt = 0;
								cancel_resetcheck_timer();
								cancel_restore_setting_check_timer();
							}
						} else {
							syslog(LOG_INFO, "Sysreset pin: Ignore last high value\n");
							TRACE(("Sysreset pin: Ignore last high value\n"));
						}
						g_sysresetpin_pressed = 0;
					} else {
						g_sysresetpin_pressed = 0;
						syslog(LOG_INFO, "Sysreset pin: Error! should not happen, val=%d\n", val);
						TRACE(("Sysreset pin: Error! should not happen, val=%d\n", val));
					}
				} else {
					syslog(LOG_INFO, "Read system reset pin error\n");
					TRACE(("Read system reset pin error\n"));
				}
			}
		}
	}

	return 0;
}


