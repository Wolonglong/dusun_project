#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>

#define GPIO_NUM 67
#define ACTIVE_LOW 1
#define LONG_PRESS_SEC 10
#define MAX_INTERVAL 1   // 连续按键间隔最大 1 秒

void run_cmd(const char *cmd)
{
    printf("Run: %s\n", cmd);
    system(cmd);
}

int gpio_read_value(int gpio)
{
    char path[128], value;
    snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/value", gpio);

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    read(fd, &value, 1);
    close(fd);

    return value == '0' ? 0 : 1;
}

int main()
{
    int current_state;
    int press_count = 0;
    time_t press_start = 0;
    time_t last_release_time = 0;

    printf("Listening GPIO %d key events...\n", GPIO_NUM);

    while (1)
    {
        current_state = gpio_read_value(GPIO_NUM);
        int pressed = (ACTIVE_LOW ? current_state == 0 : current_state == 1);

        // ================= 按下 ==================
        if (pressed && press_start == 0)
        {
            press_start = time(NULL);
        }

        // ================= 松开 ==================
        if (!pressed && press_start > 0)
        {
            time_t now = time(NULL);
            time_t duration = now - press_start;

            // ----- 长按立即触发 -----
            if (duration >= LONG_PRESS_SEC)
            {
                printf("Long press detected → factory reset\n");
                run_cmd("pkill dsled; dsled g blink_fast");
                run_cmd("cp -r /root/.backup/etc/* /etc/ ");
                usleep(3000000); // 3s
                run_cmd("reboot -f");
                press_count = 0;
            }
            else
            {
                // 记录短按次数
                press_count++;
                printf("Short press count: %d\n", press_count);

                last_release_time = now; // 记录松开时间
            }

            press_start = 0;
        }

        // ============= 超过 1 秒没按 → 判断按键序列 =============
        if (last_release_time > 0)
        {
            time_t now = time(NULL);

            if ((now - last_release_time) > MAX_INTERVAL && press_count > 0)
            {
                // 序列结束，开始判断动作
                if (press_count == 2 || press_count == 3)
                {
                    printf("Action: double press → poweroff\n");
                    run_cmd("pkill dsled; dsled r blink_fast");
                    run_cmd("cut_off_battery.sh");
                    run_cmd("poweroff");
                }
                else if (press_count == 5)
                {
                    printf("Action: 5 presses → recovery\n");
                    run_cmd("pkill dsled; dsled b blink_fast");
                    run_cmd("bootm2recovery.sh");
                }
                else
                {
                    printf("Action: %d presses → no action\n", press_count);
                }

                // 清零计数
                press_count = 0;
                last_release_time = 0;
            }
        }

        usleep(100000); // 100ms
    }

    return 0;
}
