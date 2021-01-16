#include <stdio.h>
#include <stdlib.h>
#include "Vgameboy_capture_card.h"
#include "verilated.h"

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    Vgameboy_capture_card *tb = new Vgameboy_capture_card;

    tb->CLK = 0;
    tb->BTN1 = 0;
    tb->BTN2 = 0;
    tb->eval();
    tb->CLK = 1;
    tb->eval();
    printf("BTN1: %d, BTN2: %d, LED1: %d, LED2: %d, LED3: %d\n", tb->BTN1, tb->BTN2, tb->LED1, tb->LED2, tb->LED3);
    
    tb->CLK = 0;
    tb->BTN1 = 1;
    tb->BTN2 = 0;
    tb->eval();
    tb->CLK = 1;
    tb->eval();
    printf("BTN1: %d, BTN2: %d, LED1: %d, LED2: %d, LED3: %d\n", tb->BTN1, tb->BTN2, tb->LED1, tb->LED2, tb->LED3);

    tb->CLK = 0;
    tb->BTN1 = 0;
    tb->BTN2 = 1;
    tb->eval();
    tb->CLK = 1;
    tb->eval();
    printf("BTN1: %d, BTN2: %d, LED1: %d, LED2: %d, LED3: %d\n", tb->BTN1, tb->BTN2, tb->LED1, tb->LED2, tb->LED3);

    tb->CLK = 0;
    tb->BTN1 = 1;
    tb->BTN2 = 1;
    tb->eval();
    tb->CLK = 1;
    tb->eval();
    printf("BTN1: %d, BTN2: %d, LED1: %d, LED2: %d, LED3: %d\n", tb->BTN1, tb->BTN2, tb->LED1, tb->LED2, tb->LED3);
}
