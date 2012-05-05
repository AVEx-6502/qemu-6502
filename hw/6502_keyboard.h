#ifndef QEMU_6502_KEYBOARD
#define QEMU_6502_KEYBOARD

void init_keyboard(void);
char read_char(void);
void write_char(char c);

#endif  // QEMU_6502_KEYBOARD
