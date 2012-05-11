#ifndef QEMU_6502_TIMER
#define QEMU_6502_TIMER

typedef void (*timer_callback_t)(void);

void init_timer(timer_callback_t callback);

int get_timer_value(void);
void set_timer_value(int value);

#endif  // QEMU_6502_TIMER
