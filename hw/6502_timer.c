#include "6502_timer.h"
#include <pthread.h>
#include <unistd.h>

static volatile int timer_value;
static timer_callback_t callback_func;

static void *timer_thr(void *args)
{
    while(1) {
        usleep(100 * 1000); // microseconds
        timer_value--;
        if(timer_value == 0) {
            callback_func();
            return NULL;
        }
    }
}


void init_timer(timer_callback_t callback)
{
    timer_value = 0;
    callback_func = callback;
}


int get_timer_value(void)
{
    return timer_value;
}


void set_timer_value(int value)
{
    if(timer_value == 0 && value != 0) {
        timer_value = value;
        pthread_t tid;
        pthread_create(&tid, NULL, timer_thr, NULL);
    } else {
        timer_value = value;
    }
}
