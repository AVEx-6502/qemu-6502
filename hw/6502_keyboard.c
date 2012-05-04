#include <pthread.h>
#include <stdio.h>
#include "console.h"
#include "6502_keyboard.h"

#define KEY_BUFFER_SIZE     256

#define L_SHIFT     42
#define R_SHIFT     54

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static int key_buffer[KEY_BUFFER_SIZE];
static unsigned int read_idx;
static unsigned int write_idx;


static unsigned char keymap[2][128] =  {
    // Regular map
    {
        0,
        0xFF, '1', '2', '3', '4', '5', '6', '7', '8', '9',          //1-10
        '0', '-', '=', 0xFF, 0xFF, 'q', 'w', 'e', 'r', 't',         //11-20
        'y', 'u', 'i', 'o', 'p', 0xFF, '[', '\n', 0xFF, 'a',        //21-30
        's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 0xFF, '~',          //31-40
        '\'', 0xFF, ']', 'z', 'x', 'c', 'v', 'b', 'n', 'm',         //41-50
        ',', '.', ';', 0xFF, 0xFF, 0xFF, ' ', 0xFF, 0xFF, 0xFF,     //51-60
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //61-70
        0xFF, 0xFF, 0xFF, '-', 0xFF, 0, 0xFF, '+', 0xFF, 0xFF,      //71-80
        0xFF, 0xFF, 0xFF, 0 , 0 , '\\', 0xFF, 0xFF,                 //81-90
        0
    },

    // Shift map
    {
        0,
        0xFF, '!', '@', '#', '$', '%', '?', '&', '*', '(',
        ')', '_', '+', 0xFF, 0xFF, 'Q', 'W', 'E', 'R', 'T',
        'Y', 'U', 'I', 'O', 'P', 0xFF, '{', 0xFF, 0xFF, 'A',
        'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 0xFF, '^',
        '"', 0xFF, '}', 'Z', 'X', 'C', 'V', 'B', 'N', 'M',
        '<', '>', ':', 0xFF, 0xFF, 0xFF, ' ', 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, '-', 0xFF, 0, 0xFF, '+', 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0, 0, '|',  0xFF, 0xFF,
        0
    }
};




static void key_press_6502(void *opaque, int keycode)
{
    if(keycode >= 128) {
        return;
    }

    pthread_mutex_lock(&mutex);
    key_buffer[write_idx] = keycode;
    write_idx = (write_idx + 1) % KEY_BUFFER_SIZE;
    if(write_idx == read_idx) {
        read_idx = (read_idx + 1) % KEY_BUFFER_SIZE;
    }
    pthread_mutex_unlock(&mutex);
}

static char key_to_char(int key, int shift)
{
    return keymap[shift][key];
}


void init_keyboard(void)
{
    qemu_add_kbd_event_handler(key_press_6502, NULL);
}


char read_char(void)
{
    int key, shift = 0;

    pthread_mutex_lock(&mutex);
    if(read_idx == write_idx) {
        key = 0;
    } else {
        key = key_buffer[read_idx];

        if((key == R_SHIFT || key == L_SHIFT)) {
            if((read_idx + 1) % KEY_BUFFER_SIZE == write_idx) {
                // No key after shift, ignore
                key = 0;
            } else {
                // Read next key
                shift = 1;
                key = key_buffer[read_idx+1];
                read_idx = (read_idx + 2) % KEY_BUFFER_SIZE;
            }
        } else {
            read_idx = (read_idx + 1) % KEY_BUFFER_SIZE;
        }
    }
    pthread_mutex_unlock(&mutex);

    return key_to_char(key, shift);
}

