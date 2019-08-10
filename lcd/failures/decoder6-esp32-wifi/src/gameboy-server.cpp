#include <cstring>

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/event_groups.h"

#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "nvs_flash.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>

#include "driver/gpio.h"

char ESP_WIFI_SSID[] = CONFIG_ESP_WIFI_SSID;
char ESP_WIFI_PASSWORD[] = CONFIG_ESP_WIFI_PASSWORD;
const int MAX_STA_CONNECTIONS = CONFIG_ESP_MAX_STA_CONN;
const int PORT = CONFIG_PORT;

const gpio_num_t PIN_HSYNC = GPIO_NUM_12;
const gpio_num_t PIN_D0 = GPIO_NUM_14;
const gpio_num_t PIN_D1 = GPIO_NUM_27;
const gpio_num_t PIN_CLK = GPIO_NUM_26;
const gpio_num_t PIN_VSYNC = GPIO_NUM_25;

const uint64_t PIN_ISR_SEL = GPIO_SEL_12 | GPIO_SEL_26 | GPIO_SEL_25;

static EventGroupHandle_t s_wifi_event_group;

static const char* TAG = "GameboyLCD";

const size_t SCREEN_WIDTH  = 160;
const size_t SCREEN_HEIGHT = 144;

uint8_t screen_buffer[SCREEN_HEIGHT][(SCREEN_WIDTH/4)+1];
size_t x = 0;
size_t y = 0;
bool in_bound = true;

const int IPV4_GOTIP_BIT = BIT0;
const int IPV6_GOTIP_BIT = BIT1;

const int LONG_TIME = 0xffff;
TaskHandle_t server_task = NULL;

static void IRAM_ATTR gpio_isr_vsync_handle(void*)
{
    //ESP_EARLY_LOGV(TAG, "VSYNC");

    x = 0;
    y = 0;
    in_bound = true;

    portBASE_TYPE task_woken = pdFALSE;
    xTaskNotifyFromISR( server_task, 0x1, eSetBits, &task_woken );
    if(task_woken ==  pdTRUE) {
        portYIELD_FROM_ISR();
    }
}

static void IRAM_ATTR gpio_isr_hsync_handle(void*)
{
    //ESP_EARLY_LOGV(TAG, "HSYNC");

    if(y >= SCREEN_HEIGHT) {
        in_bound = false;
        ESP_EARLY_LOGW(TAG, "HSYNC OOB: (x,y): (%d,%d)", x, y);
    }

    x = 0;
    y++;

    portBASE_TYPE task_woken = pdFALSE;
    xTaskNotifyFromISR( server_task, 0x2, eSetBits, &task_woken );
    if(task_woken ==  pdTRUE) {
        portYIELD_FROM_ISR();
    }
}

static void IRAM_ATTR gpio_isr_clk_handle(void*)
{
    //ESP_EARLY_LOGV(TAG, "CLK");
    if(x >= SCREEN_WIDTH) {
        in_bound = false;
        ESP_EARLY_LOGW(TAG, "CLK OOB: (x,y): (%d,%d)", x, y);
    }

    if(in_bound) {
        const int d0 = gpio_get_level(PIN_D0);
        const int d1 = gpio_get_level(PIN_D1);

        // Prepare packed pixels
        if((x & 0x3) == 0) {
            screen_buffer[y][(x/4)+1] = 0;    
        }

        // Shift in 2 bits from d0+d1
        screen_buffer[y][(x/4)+1] |= (d1 << 1) | (d0 << 0);
        screen_buffer[y][(x/4)+1] <<= 2;

        x++;
    } 
}

static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    switch(event->event_id) {
    case SYSTEM_EVENT_AP_STACONNECTED:
        ESP_LOGI(TAG, "station:" MACSTR " join, AID=%d",
                 MAC2STR(event->event_info.sta_connected.mac),
                 event->event_info.sta_connected.aid);
        xEventGroupSetBits(s_wifi_event_group, IPV4_GOTIP_BIT | IPV6_GOTIP_BIT);
        break;
    case SYSTEM_EVENT_AP_STADISCONNECTED:
        ESP_LOGI(TAG, "station:" MACSTR " leave, AID=%d",
                 MAC2STR(event->event_info.sta_disconnected.mac),
                 event->event_info.sta_disconnected.aid);
        break;
    default:
        break;
    }
    return ESP_OK;
}

void wifi_init_softap(void)
{
    s_wifi_event_group = xEventGroupCreate();

    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));


    wifi_config_t wifi_config;
    strncpy((char*)wifi_config.ap.ssid, ESP_WIFI_SSID, sizeof(wifi_config.ap.ssid));
    wifi_config.ap.ssid_len = strlen(ESP_WIFI_SSID);
    strncpy((char*)wifi_config.ap.password, ESP_WIFI_PASSWORD, sizeof(wifi_config.ap.password));
    wifi_config.ap.max_connection = MAX_STA_CONNECTIONS;
    wifi_config.ap.authmode = WIFI_AUTH_WPA_WPA2_PSK;

    if (strlen(ESP_WIFI_PASSWORD) == 0) {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "wifi_init_softap finished. SSID:%s password:%s",
             ESP_WIFI_SSID, ESP_WIFI_PASSWORD);
}

void setup_gpio(void) {
    gpio_config_t io_conf;
    io_conf.intr_type = GPIO_INTR_NEGEDGE;
    io_conf.pin_bit_mask = PIN_ISR_SEL;
    io_conf.mode = GPIO_MODE_INPUT;
    io_conf.pull_up_en = GPIO_PULLUP_ENABLE;
    io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
    gpio_config(&io_conf);
    gpio_install_isr_service(0);
    gpio_isr_handler_add(PIN_HSYNC, gpio_isr_hsync_handle, NULL);
    gpio_isr_handler_add(PIN_VSYNC, gpio_isr_vsync_handle, NULL);
    gpio_isr_handler_add(PIN_CLK, gpio_isr_clk_handle, NULL);
}

static void wait_for_ip()
{
    uint32_t bits = IPV4_GOTIP_BIT | IPV6_GOTIP_BIT ;

    ESP_LOGI(TAG, "Waiting for AP connection...");
    xEventGroupWaitBits(s_wifi_event_group, bits, false, true, portMAX_DELAY);
    ESP_LOGI(TAG, "Connected to AP");
}

static void serve_screen_data(int sock) {
    uint32_t ulNotifiedValue;
    size_t local_y = 0;

    struct sockaddr_in recv_addr;
    recv_addr.sin_family       = AF_INET;        
    recv_addr.sin_port         = htons(PORT);   
    //recv_addr.sin_addr.s_addr  = INADDR_BROADCAST;
    inet_pton(AF_INET, "192.168.4.2", &recv_addr.sin_addr);


    while(1) {
        xTaskNotifyWait( 0, ULONG_MAX, &ulNotifiedValue, portMAX_DELAY );

         /* Process any events that have been latched in the notified value. */

        if( ( ulNotifiedValue & 0x01 ) != 0 )
        {
            ESP_LOGI(TAG, "Vsync, y: %d", local_y);
            local_y = 0;

        }

        if( ( ulNotifiedValue & 0x02 ) != 0 )
        {
            //int err = send(sock, &screen_buffer[local_y], (SCREEN_WIDTH/4)+1, 0);
            int err = sendto(sock, &screen_buffer[local_y], (SCREEN_WIDTH/4)+1, 0, (sockaddr *)&recv_addr, sizeof(recv_addr));
            if (err < 0) {
                ESP_LOGE(TAG, "Error occured during sending: errno %d", errno);
                break;
            }

            local_y++;
        }

        /*int err = send(sock, rx_buffer, len, 0);
        if (err < 0) {
            ESP_LOGE(TAG, "Error occured during sending: errno %d", errno);
            break;
        }*/
    }
}

static void tcp_server_task(void *pvParameters)
{
    char addr_str[128];
    int addr_family;
    int ip_protocol;

    while (1) {

#ifdef CONFIG_IPV4
        struct sockaddr_in destAddr;
        destAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        destAddr.sin_family = AF_INET;
        destAddr.sin_port = htons(PORT);
        addr_family = AF_INET;
        ip_protocol = IPPROTO_IP;
        inet_ntoa_r(destAddr.sin_addr, addr_str, sizeof(addr_str) - 1);
#else // IPV6
        struct sockaddr_in6 destAddr;
        bzero(&destAddr.sin6_addr.un, sizeof(destAddr.sin6_addr.un));
        destAddr.sin6_family = AF_INET6;
        destAddr.sin6_port = htons(PORT);
        addr_family = AF_INET6;
        ip_protocol = IPPROTO_IPV6;
        inet6_ntoa_r(destAddr.sin6_addr, addr_str, sizeof(addr_str) - 1);
#endif

        int sock = socket(addr_family, SOCK_DGRAM, ip_protocol);
        if (sock < 0) {
            ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
            break;
        }
        ESP_LOGI(TAG, "Socket created");

        /* int optval = 1;
        int err = setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval));
        if (err != 0) {
            ESP_LOGE(TAG, "Socket unable to set broadcast: errno %d", errno);
            break;
        }*/

        serve_screen_data(sock);

        if (sock != -1) {
            ESP_LOGE(TAG, "Shutting down socket and restarting...");
            shutdown(sock, 0);
            close(sock);
        }
    }
    vTaskDelete(NULL);
}

extern "C" void app_main(void)
{
    //Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    for(size_t y = 0; y < SCREEN_HEIGHT; y++) {
        screen_buffer[y][0] = y;
    }
    
    ESP_LOGI(TAG, "ESP_WIFI_MODE_AP");
    wifi_init_softap();

    wait_for_ip();

    xTaskCreate(tcp_server_task, "tcp_server", 4096, NULL, 5, &server_task);

    setup_gpio();
}