
/*
 * QEMU Alpha DP264/CLIPPER hardware system emulator.
 *
 * Choose CLIPPER IRQ mappings over, say, DP264, MONET, or WEBBRICK
 * variants because CLIPPER doesn't have an SMC669 SuperIO controller
 * that we need to emulate as well.
 */

#include "6502_new.h"

#ifdef USE_NEW_6502

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
    cpu = cpu_init("ev67");
    cpu->trap_arg0 = ram_size; //0x10000;
    cpu->trap_arg1 = 0;
    cpu->trap_arg2 = 1;

    MemoryRegion *address_space = get_system_memory();


#if 0   // This should work but it doesn't...
    /*
     * Address Range  |   Function
     * ---------------+------------------
     * $0000 - $007F  | TIA registers
     * $0080 - $00FF  |     RAM
     * $0200 - $02FF  | RIOT registers
     * $1000 - $1FFF  |     ROM
     */

    // TIA registers
    MemoryRegion *tia_regs = g_malloc(sizeof(*tia_regs));
    memory_region_init_io(tia_regs, &tia_ops, cpu, "6502.tia_regs", 0x007F - 0x0000 + 1);
    memory_region_add_subregion(address_space, 0x0000, tia_regs);

    // RAM
    MemoryRegion *ram = g_malloc(sizeof(*ram));
    memory_region_init_ram(ram, "6502.ram", 0x00FF - 0x0080 + 1);
    vmstate_register_ram_global(ram);
    memory_region_add_subregion(address_space, 0x0080, ram);

    // Unused space between RAM and RIOT registers
    MemoryRegion *unused1 = g_malloc(sizeof(*unused1));;
    memory_region_init_reservation(unused1, "6502.unused1", 0x01FF - 0x0100 + 1);
    memory_region_add_subregion(address_space, 0x0100, unused1);

    // RIOT registers
    MemoryRegion *riot_regs = g_malloc(sizeof(*riot_regs));;
    memory_region_init_io(riot_regs, &riot_ops, cpu, "6502.riot_regs", 0x02FF - 0x0200 + 1);
    memory_region_add_subregion(address_space, 0x0200, riot_regs);

    // Unused space between RIOT registers and ROM
    MemoryRegion *unused2 = g_malloc(sizeof(*unused2));
    memory_region_init_reservation(unused2, "6502.unused2", 0x0FFF - 0x0300 + 1);
    memory_region_add_subregion(address_space, 0x0300, unused2);

    // ROM
    MemoryRegion *rom = g_malloc(sizeof(*rom));
    memory_region_init_ram(rom, "6502.rom", 0x1FFF - 0x1000 + 1);
    memory_region_set_readonly(rom, true);
    vmstate_register_ram_global(rom);
    memory_region_add_subregion(address_space, 0x1000, rom);

    // Rest of the address space
    MemoryRegion *unused3 = g_malloc(sizeof(*unused3));
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

    MemoryRegion *ram = g_new(MemoryRegion, 1);
    memory_region_init_ram(ram, "6502.ram", 0x10000);   // 64 KB of RAM
    vmstate_register_ram_global(ram);
    memory_region_add_subregion(address_space, 0, ram);

    // Load ROM
    if(bios_name == NULL) {
        bios_name = BIOS_FILENAME;
    }

    // 4 KB of BIOS starting at 0x1000
    if(load_image_targphys(bios_name, 0x1000, 0x1FFF - 0x1000 + 1) < 0) {
        fprintf(stderr, "Error loading bios file: %s\nRunning with empty memory.\n", bios_name);
        //exit(-1);
    }

#endif


    // TODO: Clean-up
    cpu->pal_mode = 1;
    cpu->pc = 0x1000;   // BIOS address
    cpu->palbr = 0x1000;

    fprintf(stderr, "Final do mos6502_init.\n");

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





// -----------------------------------------------------------------------------






#else

#include "hw.h"
#include "elf.h"
#include "loader.h"
#include "boards.h"
#include "6502_sys.h"
#include "sysemu.h"
#include "mc146818rtc.h"
#include "ide.h"
#include "i8254.h"

#define MAX_IDE_BUS 2

static uint64_t cpu_alpha_superpage_to_phys(void *opaque, uint64_t addr)
{
    if (((addr >> 41) & 3) == 2) {
        addr &= 0xffffffffffull;
    }
    return addr;
}

/* Note that there are at least 3 viewpoints of IRQ numbers on Alpha systems.
    (0) The dev_irq_n lines into the cpu, which we totally ignore,
    (1) The DRIR lines in the typhoon chipset,
    (2) The "vector" aka mangled interrupt number reported by SRM PALcode,
    (3) The interrupt number assigned by the kernel.
   The following function is concerned with (1) only.  */

static int clipper_pci_map_irq(PCIDevice *d, int irq_num)
{
    int slot = d->devfn >> 3;

    assert(irq_num >= 0 && irq_num <= 3);

    return (slot + 1) * 4 + irq_num;
}

static void clipper_init(ram_addr_t ram_size,
                         const char *boot_device,
                         const char *kernel_filename,
                         const char *kernel_cmdline,
                         const char *initrd_filename,
                         const char *cpu_model)
{
    CPUState *cpus[4];
    PCIBus *pci_bus;
    ISABus *isa_bus;
    qemu_irq rtc_irq;
    long size, i;
    const char *palcode_filename;
    uint64_t palcode_entry, palcode_low, palcode_high;
    uint64_t kernel_entry, kernel_low, kernel_high;

    /* Create up to 4 cpus.  */
    memset(cpus, 0, sizeof(cpus));
    for (i = 0; i < smp_cpus; ++i) {
        cpus[i] = cpu_init(cpu_model ? cpu_model : "ev67");
    }

    cpus[0]->trap_arg0 = ram_size;
    cpus[0]->trap_arg1 = 0;
    cpus[0]->trap_arg2 = smp_cpus;

    /* Init the chipset.  */
    pci_bus = typhoon_init(ram_size, &isa_bus, &rtc_irq, cpus,
                           clipper_pci_map_irq);

    rtc_init(isa_bus, 1980, rtc_irq);
    pit_init(isa_bus, 0x40, 0, NULL);
    isa_create_simple(isa_bus, "i8042");

    /* VGA setup.  Don't bother loading the bios.  */
    alpha_pci_vga_setup(pci_bus);

    /* Serial code setup.  */
    for (i = 0; i < MAX_SERIAL_PORTS; ++i) {
        if (serial_hds[i]) {
            serial_isa_init(isa_bus, i, serial_hds[i]);
        }
    }

    /* Network setup.  e1000 is good enough, failing Tulip support.  */
    for (i = 0; i < nb_nics; i++) {
        pci_nic_init_nofail(&nd_table[i], "e1000", NULL);
    }

    /* IDE disk setup.  */
    {
        DriveInfo *hd[MAX_IDE_BUS * MAX_IDE_DEVS];
        ide_drive_get(hd, MAX_IDE_BUS);

        pci_cmd646_ide_init(pci_bus, hd, 0);
    }

    /* Load PALcode.  Given that this is not "real" cpu palcode,
       but one explicitly written for the emulation, we might as
       well load it directly from and ELF image.  */
    palcode_filename = (bios_name ? bios_name : "palcode-clipper");
    palcode_filename = qemu_find_file(QEMU_FILE_TYPE_BIOS, palcode_filename);
    if (palcode_filename == NULL) {
        hw_error("no palcode provided\n");
        exit(1);
    }
    size = load_elf(palcode_filename, cpu_alpha_superpage_to_phys,
                    NULL, &palcode_entry, &palcode_low, &palcode_high,
                    0, EM_ALPHA, 0);
    if (size < 0) {
        hw_error("could not load palcode '%s'\n", palcode_filename);
        exit(1);
    }

    /* Start all cpus at the PALcode RESET entry point.  */
    for (i = 0; i < smp_cpus; ++i) {
        cpus[i]->pal_mode = 1;
        cpus[i]->pc = palcode_entry;
        cpus[i]->palbr = palcode_entry;
    }

    /* Load a kernel.  */
    if (kernel_filename) {
        uint64_t param_offset;

        size = load_elf(kernel_filename, cpu_alpha_superpage_to_phys,
                        NULL, &kernel_entry, &kernel_low, &kernel_high,
                        0, EM_ALPHA, 0);
        if (size < 0) {
            hw_error("could not load kernel '%s'\n", kernel_filename);
            exit(1);
        }

        cpus[0]->trap_arg1 = kernel_entry;

        param_offset = kernel_low - 0x6000;

        if (kernel_cmdline) {
            pstrcpy_targphys("cmdline", param_offset, 0x100, kernel_cmdline);
        }

        if (initrd_filename) {
            long initrd_base, initrd_size;

            initrd_size = get_image_size(initrd_filename);
            if (initrd_size < 0) {
                hw_error("could not load initial ram disk '%s'\n",
                         initrd_filename);
                exit(1);
            }

            /* Put the initrd image as high in memory as possible.  */
            initrd_base = (ram_size - initrd_size) & TARGET_PAGE_MASK;
            load_image_targphys(initrd_filename, initrd_base,
                                ram_size - initrd_base);

            stq_phys(param_offset + 0x100, initrd_base + 0xfffffc0000000000ULL);
            stq_phys(param_offset + 0x108, initrd_size);
        }
    }
}

static QEMUMachine clipper_machine = {
    .name = "clipper",
    .desc = "Alpha DP264/CLIPPER",
    .init = clipper_init,
    .max_cpus = 4,
    .is_default = 1,
};

static void clipper_machine_init(void)
{
    qemu_register_machine(&clipper_machine);
}

machine_init(clipper_machine_init);

#endif
