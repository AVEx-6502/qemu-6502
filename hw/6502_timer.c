#include <pthread.h>
#include <unistd.h>
#include "6502_timer.h"


static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static int timer_value;
static timer_callback_t callback_func;

static void *timer_thr(void *args)
{
    while(1) {
        usleep(100 * 1000); // microseconds
        pthread_mutex_lock(&mutex);
        timer_value--;
        if(timer_value == 0) {
            callback_func();
            pthread_mutex_unlock(&mutex);
            return NULL;
        }
        pthread_mutex_unlock(&mutex);
    }
}


void init_timer(timer_callback_t callback)
{
    timer_value = 0;
    callback_func = callback;
}


int get_timer_value(void)
{
    int ret;
    pthread_mutex_lock(&mutex);
    ret = timer_value;
    pthread_mutex_unlock(&mutex);
    return ret;
}


void set_timer_value(int value)
{
    pthread_mutex_lock(&mutex);
    if(timer_value == 0 && value != 0) {
        timer_value = value;
        pthread_t tid;
        pthread_create(&tid, NULL, timer_thr, NULL);
    } else {
        timer_value = value;
    }
    pthread_mutex_unlock(&mutex);
}
