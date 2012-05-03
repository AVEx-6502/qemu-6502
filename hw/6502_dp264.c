/*
 * QEMU MOS 6502 hardware system emulator.
 *
 */

#include "hw.h"
#include "boards.h"
#include "loader.h"
#include "sysemu.h"
#include "exec-memory.h"


#define BIOS_FILENAME      "6502_bios.rom"


static uint64_t tia_read(void *opaque, target_phys_addr_t addr, unsigned size)
{
    fprintf(stderr, "Reading TIA address %llu.\n", (unsigned long long)addr);
    return 0;
}


static void tia_write(void *opaque, target_phys_addr_t addr, uint64_t value, unsigned size)
{
    fprintf(stderr, "Writting %llu in TIA address %llu.\n", (unsigned long long)value, (unsigned long long)addr);
}


static uint64_t riot_read(void *opaque, target_phys_addr_t addr, unsigned size)
{
    fprintf(stderr, "Reading RIOT address %llu.\n", (unsigned long long)addr);
    return 0;
}


static void riot_write(void *opaque, target_phys_addr_t addr,uint64_t value, unsigned size)
{
    fprintf(stderr, "Writting %llu in RIOT address %llu.\n", (unsigned long long)value, (unsigned long long)addr);
}



static const MemoryRegionOps tia_ops = {
    .read = tia_read,
    .write = tia_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 1,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 1,
    },
};


static const MemoryRegionOps riot_ops = {
    .read = riot_read,
    .write = riot_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 1,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 1,
    },
};




static void mos6502_init(ram_addr_t ram_size,
                         const char *boot_device,
                         const char *kernel_filename,
                         const char *kernel_cmdline,
                         const char *initrd_filename,
                         const char *cpu_model)
{
    CPUState *cpu;

    // TODO: Clean this after changing CPUState struct
    cpu = cpu_init(NULL);
    cpu->trap_arg0 = 0x10000;   //ram_size;
    cpu->trap_arg1 = 0;
    cpu->trap_arg2 = 1;

    MemoryRegion *address_space = get_system_memory();


#if 0   // This should work but it doesn't...
    /*
     * Address Range  |   Function      |       Size
     * ---------------+-----------------+----------------------
     * $0000 - $007F  | TIA registers   |     128 bytes
     * $0080 - $00FF  |     RAM         |     128 bytes
     * $0100 - $01FF  |     RAM (stack) |     256 bytes
     * $0200 - $02FF  | RIOT registers  |     256 bytes
     * $0300 - $0FFF  |  ?????????      |    3328 bytes = 3,25 KB
     * $1000 - $1FFF  |     ROM         |    4096 bytes = 4,00 KB
     */

    // TIA registers
    MemoryRegion *tia_regs = g_new(MemoryRegion, 1);
    memory_region_init_io(tia_regs, &tia_ops, cpu, "6502.tia_regs", 0x007F - 0x0000 + 1);
    memory_region_add_subregion(address_space, 0x0000, tia_regs);

    // RAM
    MemoryRegion *ram = g_new(MemoryRegion, 1);
    memory_region_init_ram(ram, "6502.ram", 0x00FF - 0x0080 + 1);
    vmstate_register_ram_global(ram);
    memory_region_add_subregion(address_space, 0x0080, ram);

    // Unused space between RAM and RIOT registers
    MemoryRegion *unused1 = g_new(MemoryRegion, 1);
    memory_region_init_reservation(unused1, "6502.unused1", 0x01FF - 0x0100 + 1);
    memory_region_add_subregion(address_space, 0x0100, unused1);

    // RIOT registers
    MemoryRegion *riot_regs = g_new(MemoryRegion, 1);
    memory_region_init_io(riot_regs, &riot_ops, cpu, "6502.riot_regs", 0x02FF - 0x0200 + 1);
    memory_region_add_subregion(address_space, 0x0200, riot_regs);

    // Unused space between RIOT registers and ROM
    MemoryRegion *unused2 = g_new(MemoryRegion, 1);
    memory_region_init_reservation(unused2, "6502.unused2", 0x0FFF - 0x0300 + 1);
    memory_region_add_subregion(address_space, 0x0300, unused2);

    // ROM
    MemoryRegion *rom = g_new(MemoryRegion, 1);
    memory_region_init_ram(rom, "6502.rom", 0x1FFF - 0x1000 + 1);
    memory_region_set_readonly(rom, true);
    vmstate_register_ram_global(rom);
    memory_region_add_subregion(address_space, 0x1000, rom);

    // Rest of the address space
    MemoryRegion *unused3 = g_new(MemoryRegion, 1);
    memory_region_init_reservation(unused3, "6502.unused3", (ram_size - 1) - 0x2000 + 1);
    memory_region_add_subregion(address_space, 0x2000, unused3);

    // Load ROM
    if(bios_name == NULL) {
        bios_name = BIOS_FILENAME;
    }

    if(load_image_targphys(bios_name, 0x1000, 0x1FFF - 0x1000 + 1) < 0) {
        fprintf(stderr, "Error loading bios file: %s\n", bios_name);
        exit(-1);
    }
#else
/*
    MemoryRegion *ram = g_new(MemoryRegion, 1);
    memory_region_init_ram(ram, "6502.ram", 0x10000 - 0x0000);
    vmstate_register_ram_global(ram);
    memory_region_add_subregion(address_space, 0, ram);
*/

    // RAM
    MemoryRegion *ram = g_malloc(sizeof(*ram));
    memory_region_init_ram(ram, "6502.ram", ram_size);
    vmstate_register_ram_global(ram);

    MemoryRegion *ram_below_32k = g_malloc(sizeof(*ram_below_32k));
    memory_region_init_alias(ram_below_32k, "ram-below-32k", ram, 0x0000, 0x8000);
    memory_region_add_subregion(address_space, 0x0000, ram_below_32k);

    MemoryRegion *ram_above_32k = g_malloc(sizeof(*ram_above_32k));
    memory_region_init_alias(ram_above_32k, "ram-above-32k", ram, 0x8000, 0x8000);
    memory_region_add_subregion(address_space, 0x8000, ram_above_32k);


    // TIA registers
    MemoryRegion *tia_regs = g_new(MemoryRegion, 1);
    memory_region_init_io(tia_regs, &tia_ops, cpu, "6502.tia_regs", 0x0080);

    MemoryRegion *tia_regs_alias = g_new(MemoryRegion, 1);
    memory_region_init_alias(tia_regs_alias, "tia_regs", tia_regs, 0x0000, 0x0080);
    memory_region_add_subregion_overlap(address_space, 0x0000, tia_regs_alias, 0);

    // Load ROM
    if(bios_name == NULL) {
        bios_name = BIOS_FILENAME;
    }

    // 4 KB of BIOS starting at 0x1000
    if(load_image_targphys(bios_name, 0x1000, 0x1FFF - 0x1000 + 1) < 0) {
        fprintf(stderr, "Error loading bios file: %s\n", bios_name);
        exit(-1);
    }

#endif

    cpu->pc = 0x1000;   // BIOS address

}

static QEMUMachine mos6502_machine = {
    .name = "mos6502",
    .desc = "MOS 6502 CPU",
    .init = mos6502_init,
    .max_cpus = 1,
    .is_default = 1,
};

static void mos6502_machine_init(void)
{
    qemu_register_machine(&mos6502_machine);
}

machine_init(mos6502_machine_init);
