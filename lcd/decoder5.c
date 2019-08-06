//gcc -Wall -Werror -o decoder5 -O3 decoder5.c

#include <time.h>
#include <pthread.h>
#include <stdint.h>
#include "gpio.h"

typedef unsigned int    uint32; 
typedef signed int      int32; 
typedef unsigned short    uint16; 

void short_wait(void);		// used as pause between clocked GPIO changes
unsigned bcm_host_get_peripheral_address(void);		// find Pi 2 or Pi's gpio base address
static unsigned get_dt_ranges(const char *filename, unsigned offset); // Pi 2 detect

struct bcm2835_peripheral gpio;	// needs initialisation

// PART 1 - GPIO and RT process stuff ----------------------------------

// GPIO setup macros. Always use INP_GPIO(x) before using OUT_GPIO(x)
#define INP_GPIO(g)   *(gpio.addr + ((g)/10)) &= ~(7<<(((g)%10)*3))
#define OUT_GPIO(g)   *(gpio.addr + ((g)/10)) |=  (1<<(((g)%10)*3))
#define SET_GPIO_ALT(g,a) *(gpio.addr + (((g)/10))) |= (((a)<=3?(a) + 4:(a)==4?3:2)<<(((g)%10)*3))
 
#define GPIO_SET  *(gpio.addr + 7)  // sets   bits which are 1 ignores bits which are 0
#define GPIO_CLR  *(gpio.addr + 10) // clears bits which are 1 ignores bits which are 0
 
#define GPIO_READ(g)  *(gpio.addr + 13) &= (1<<(g))
#define GPIO_READALL *(gpio.addr + 13)

#define GPIO_PULL *(gpio.addr + 37) // pull up/pull down
#define GPIO_PULLCLK0 *(gpio.addr + 38) // pull up/pull down clock


const uint32 inputs = (1 << 2) | (1 << 3) | (1 << 6) | (1 << 5) | (1 << 7);
uint8_t screen_buffer[144][160];
 
// Exposes the physical address defined in the passed structure using mmap on /dev/mem
int map_peripheral(struct bcm2835_peripheral *p)
{
   if ((p->mem_fd = open("/dev/mem", O_RDWR|O_SYNC) ) < 0) {
      printf("Failed to open /dev/mem, try checking permissions.\n");
      return -1;
   }
   p->map = mmap(
      NULL, BLOCK_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED,
      p->mem_fd,      	// File descriptor to physical memory virtual file '/dev/mem'
      p->addr_p);       // Address in physical map that we want this memory block to expose
   if (p->map == MAP_FAILED) {
        perror("mmap");
        return -1;
   }
   p->addr = (volatile unsigned int *)p->map;
   return 0;
}
 
void unmap_peripheral(struct bcm2835_peripheral *p) 
{	munmap(p->map, BLOCK_SIZE);
	close(p->mem_fd);
}

int main(void) {
    gpio.addr_p = bcm_host_get_peripheral_address() +  + 0x200000;
	if (gpio.addr_p == 0x20200000) printf("RPi Plus detected\n");
	else printf("RPi 2 detected\n");

	// set thread to real time priority -----------------
	struct sched_param sp;
	sp.sched_priority = 98; // maybe 99, 32, 31?
	if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp))
	{ fprintf(stderr, "warning: failed to set RT priority\n"); }
	// --------------------------------------------------
	if(map_peripheral(&gpio) == -1) 
	{	printf("Failed to map the physical GPIO registers into the virtual memory space.\n");
		return -1;
	}

    // Set pins as input
    INP_GPIO(2);
    INP_GPIO(3);
    INP_GPIO(6);
    INP_GPIO(5);
    INP_GPIO(7);

    // Setup pull-up on pins 2,3,6,5,7
    GPIO_PULL = 2;	// pull-up
	short_wait();	// must wait 150 cycles
    GPIO_PULLCLK0 = (1 << 2) | (1 << 3) | (1 << 6) | (1 << 5) | (1 << 7);
    short_wait();
	GPIO_PULL = 0; // reset GPPUD register
	short_wait();
	GPIO_PULLCLK0 = 0; // remove clock
	short_wait(); // probably unnecessary

    uint32 state_old = 0;
    uint32 state = 0;
    //uint32 pixels = 0;
    //time_t start;
    //time_t now;
    //time(&start);
    uint32_t frames = 0;
    for (;;) {
        for(; ((state_old & (1<<7))==0) || ((state & (1<<7))!=0); state_old = state, state = gpio.addr[13]) {} // Vsync
        for (uint8_t y = 0; y < 144; y++) {
            for(; ((state_old & (1<<2))==0) || ((state & (1<<2))!=0); state_old = state, state = gpio.addr[13]) {} // Hsync
            for (uint8_t x = 0; x < 160; x++) {
                for(; ((state_old & (1<<5))==0) || ((state & (1<<5))!=0); state_old = state, state = gpio.addr[13]) {} //CLK

                // d0 = state & ...
                const uint8_t d0 = ((state & (1<<3)) >> 3);
                // d1 = state & ...
                const uint8_t d1 = ((state & (1<<6)) >> 6);
                const uint8_t color = (d1 << 1) | d0;
                screen_buffer[y][x] = color;
            }
		}
        state_old = 0;

        frames++;
        if (frames % 60 == 0) {
            //time(&now);
            //printf("Frames: %d, pixels: %d, T: %ld, FPS: %f\n", frames, pixels, now-start, frames/(double)(now-start));
            for (uint8_t y = 0; y < 144; y++) {
                for (uint8_t x = 0; x < 160; x++) {
                    switch(screen_buffer[y][x]) {
                        case 0:
                            putc(' ', stdout);
                            break;
                        case 1:
                            putc('.', stdout);
                            break;
                        case 2:
                            putc('o', stdout);
                            break;
                        case 3:
                            putc('#', stdout);
                            break;
                    }
                }
                putc('\n', stdout);
            }
        }
    }

    return 0;
}

void short_wait(void)					// creates pause required in between clocked GPIO settings changes
{
//	int i;
//	for (i=0; i<150; i++) {
//		asm volatile("nop");
//	}
	fflush(stdout); //
	usleep(1); // suggested as alternative for asm which c99 does not accept
}

unsigned bcm_host_get_peripheral_address(void)		// find Pi 2 or Pi's gpio base address
{
   unsigned address = get_dt_ranges("/proc/device-tree/soc/ranges", 4);
   return address == ~0 ? 0x20000000 : address;
}
static unsigned get_dt_ranges(const char *filename, unsigned offset)
{
   unsigned address = ~0;
   FILE *fp = fopen(filename, "rb");
   if (fp)
   {
      unsigned char buf[4];
      fseek(fp, offset, SEEK_SET);
      if (fread(buf, 1, sizeof buf, fp) == sizeof buf)
      address = buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3] << 0;
      fclose(fp);
   }
   return address;
}
