#include <linux/highmem.h>
#include <linux/hrtimer.h>
#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mod_devicetable.h>
#include <linux/mm.h>
#include <linux/objtool.h>
#include <linux/sched.h>
#include <linux/sched/smt.h>
#include <linux/slab.h>
#include <linux/tboot.h>
#include <linux/trace_events.h>
#include <linux/entry-kvm.h>

#include <asm/apic.h>
#include <asm/asm.h>
#include <asm/cpu.h>
#include <asm/cpu_device_id.h>
#include <asm/debugreg.h>
#include <asm/desc.h>
#include <asm/fpu/api.h>
#include <asm/fpu/xstate.h>
#include <asm/idtentry.h>
#include <asm/io.h>
#include <asm/irq_remapping.h>
#include <asm/kexec.h>
#include <asm/perf_event.h>
#include <asm/mmu_context.h>
#include <asm/mshyperv.h>
#include <asm/mwait.h>
#include <asm/spec-ctrl.h>
#include <asm/virtext.h>
#include <asm/vmx.h>

#include "capabilities.h"
#include "cpuid.h"
#include "evmcs.h"
#include "hyperv.h"
#include "kvm_onhyperv.h"
#include "irq.h"
#include "kvm_cache_regs.h"
#include "lapic.h"
#include "mmu.h"
#include "nested.h"
#include "pmu.h"
#include "sgx.h"
#include "trace.h"
#include "vmcs.h"
#include "vmcs12.h"
#include "vmx.h"
#include "introspection.h"
#include "introspection_wintypes.h"
#include "x86.h"

#define ZYAN_NO_LIBC
#include <Zydis/Zydis.h>

#define DEFINE_MEMORY_OPERATION(name, type) \
	type intro_read_virt##name(struct kvm_vcpu* vcpu, gva_t addr) {  \
        	type ret;						 \
		intro_read_virt(vcpu, addr, &ret, sizeof(type));	 \
        	return ret; 						 \
	}								 \
									 \
	void intro_write_virt##name(struct kvm_vcpu* vcpu, gva_t addr, type value) { \
		intro_write_virt(vcpu, addr, &value, sizeof(type));		     \
	}                                                               \
                                                                        \
	type intro_read_phys##name(struct kvm_vcpu* vcpu, gpa_t addr) { \
        	type ret;						 \
		intro_read_phys(vcpu, addr, &ret, sizeof(type));	 \
        	return ret; 						 \
	}								 \
									 \
	void intro_write_phys##name(struct kvm_vcpu* vcpu, gpa_t addr, type value) { \
		intro_write_phys(vcpu, addr, &value, sizeof(type));		     \
	}


struct windows_context {
	u64 PsLoadedModuleList;
};

struct pe_export {
	char name[256];
	gva_t address;
	gva_t address_rva;
};

struct pe_header {
	struct xarray exports;
	u32 export_count;
};

typedef void(*disassemble_callback_t)(ZydisDecodedInstruction*, u64);
typedef void(*disassemble_text_callback_t)(ZydisDecodedInstruction*, const char*, u64);

void intro_disassemble(hva_t addr, gva_t rip, u32 len, disassemble_callback_t callback) {
	ZydisDecoder decoder;
	ZydisDecodedInstruction instruction;
	ZyanUSize offset = 0, length = len;
	ZyanU64 runtime_address = rip;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];

	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, (u8*)addr + offset, length - offset,
						   &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE,
						   ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY)))
	{
		callback(&instruction, runtime_address);

		offset += instruction.length;
		runtime_address += instruction.length;
	}
}

void intro_disassemble_text(hva_t addr, gva_t rip, u32 len, disassemble_text_callback_t callback) {
	ZydisDecoder decoder;
	ZydisFormatter formatter;
	ZydisDecodedInstruction instruction;
	ZyanUSize offset = 0, length = len;
	ZyanU64 runtime_address = rip;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, (u8*)addr + offset, length - offset,
						   &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE,
						   ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY)))
	{
		char buffer[256];
		ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
						instruction.operand_count_visible, buffer, sizeof(buffer), runtime_address);
		callback(&instruction, buffer, runtime_address);

		offset += instruction.length;
		runtime_address += instruction.length;
	}
}

void intro_read_virt(struct kvm_vcpu* vcpu, gva_t addr, void* buffer, u32 len) {
	struct x86_exception e;
	kvm_read_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, addr, &e), buffer, len);
}

void intro_write_virt(struct kvm_vcpu* vcpu, gva_t addr, void* buffer, u32 len) {
	struct x86_exception e;
	kvm_write_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, addr, &e), buffer, len);
}

void intro_read_phys(struct kvm_vcpu* vcpu, gpa_t addr, void* buffer, u32 len) {
	kvm_read_guest(vcpu->kvm, addr, buffer, len);
}

void intro_write_phys(struct kvm_vcpu* vcpu, gpa_t addr, void* buffer, u32 len) {
	kvm_write_guest(vcpu->kvm, addr, buffer, len);
}

void intro_read_wstr(struct kvm_vcpu* vcpu, struct _UNICODE_STRING* ustr, char* buffer, u32 len) {
	u32 name_size = ustr->Length;
	u16* name_buffer = kzalloc(name_size + 2, GFP_KERNEL_ACCOUNT);
	intro_read_virt(vcpu, (gva_t)ustr->Buffer, name_buffer, name_size);

	u32 i;
	for (i = 0; (i < len - 1) && (name_buffer[i] != 0); i++)
		buffer[i] = (char)name_buffer[i];

	buffer[i] = 0;
}

hva_t intro_map_virt(struct kvm_vcpu *vcpu, gva_t addr, struct kvm_host_map* map) {
	gpa_t gpa = kvm_mmu_gva_to_gpa_read(vcpu, addr, NULL);
	if (kvm_vcpu_map(vcpu, gpa_to_gfn(gpa), map))
		return 0;

	if (!map->hva)
		return 0;

	return (hva_t)(map->hva + offset_in_page(gpa));
}

void intro_unmap(struct kvm_vcpu *vcpu, struct kvm_host_map* map) {
	kvm_vcpu_unmap(vcpu, map, true);
}

DEFINE_MEMORY_OPERATION(64, u64);
DEFINE_MEMORY_OPERATION(32, u32);
DEFINE_MEMORY_OPERATION(16, u16);
DEFINE_MEMORY_OPERATION(8, u8);

#define intro_pe_for_each_export(idx, export, pe) \
	xa_for_each_range(&pe->exports, idx, export, 0, \
			  (pe->export_count - 1))

#define intro_pe_for_each_export_ref(idx, export, pe) \
	xa_for_each_range(&pe.exports, idx, export, 0, \
			  (pe.export_count - 1))


bool intro_init_win_context(struct windows_context* ctx);

bool intro_init_pe(struct kvm_vcpu* vcpu, gva_t address, struct pe_header* pe) {
	struct _IMAGE_DOS_HEADER dos_header;
	struct _IMAGE_NT_HEADERS64 nt_headers;
	struct _IMAGE_EXPORT_DIRECTORY export_directory;

	intro_read_virt(vcpu, address, &dos_header, sizeof(struct _IMAGE_DOS_HEADER));
	intro_read_virt(vcpu, address + dos_header.e_lfanew, &nt_headers, sizeof(struct _IMAGE_NT_HEADERS64));
	intro_read_virt(vcpu, address + nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
			&export_directory, sizeof(struct _IMAGE_EXPORT_DIRECTORY));

	xa_init(&pe->exports);
	for (u32 index = 0; index < export_directory.NumberOfNames; index++) {
		struct pe_export* export = kzalloc(sizeof(struct pe_export), GFP_KERNEL);

		u32 ordinal = intro_read_virt16(vcpu, address + export_directory.AddressOfNameOrdinals + (index * 0x2));
		u32 func_addr = intro_read_virt32(vcpu, address + export_directory.AddressOfFunctions + (ordinal * sizeof(ULONG)));
		u32 name_addr = intro_read_virt32(vcpu, address + export_directory.AddressOfNames + (index * sizeof(ULONG)));
		intro_read_virt(vcpu, address + name_addr, export->name, sizeof(export->name));

		export->address = address + func_addr;
		export->address_rva = func_addr;

		xa_insert(&pe->exports, pe->export_count++, export, GFP_KERNEL_ACCOUNT);
	}

	return true;
}

void intro_free_pe(struct pe_header* pe) {
	unsigned long i;
	struct pe_export* export;

	intro_pe_for_each_export(i, export, pe) {
		kfree(export);
		xa_erase(&pe->exports, i);
	}
}

struct pe_export* intro_find_export_pe(struct pe_header* pe, const char* name) {
	unsigned long i;
	struct pe_export* export;

	intro_pe_for_each_export(i, export, pe) {
		if (!strcmp(export->name, name))
			return export;
	}

	return NULL;
}

/* https://github.com/ufrisk/MemProcFS/blob/fd9aa0219b29c5916b8f036ee3b1e0d1f486e14d/vmm/vmmwininit.c#L597 */
gva_t intro_get_ntoskrnl_entrypoint(struct kvm_vcpu* vcpu) {
	u8 buf[0x1000];
	for (u32 index = 0; index < 100; index++) {
		memset(buf, 0, sizeof(buf));

		gpa_t addr = index * 0x1000;
		intro_read_phys(vcpu, addr, buf, 0x1000);

		u64 start_bytes = *(u64*)(buf);
		if (0x00000001000600E9 ^ (0xffffffffffff00ff & start_bytes))
			continue;

		gva_t kernel_entrypoint = *(gva_t*)(buf + 0x70);
		if (0xfffff80000000000 ^ (0xfffff80000000000 & kernel_entrypoint))
			continue;

		u64 pml4 = *(u64*)(buf + 0xa0);
		if (0xffffff0000000fff & pml4)
			continue;

		return kernel_entrypoint;
	}

	return 0;
}

gva_t intro_get_ntoskrnl(struct kvm_vcpu* vcpu) {
	gva_t entrypoint = intro_get_ntoskrnl_entrypoint(vcpu) & ~( PAGE_SIZE - 1 );

	for ( u64 index = 0; index < 0x1000000 && entrypoint > 0; index++ ) {
		u16 mz_header = intro_read_virt16(vcpu, entrypoint);
		if (mz_header != 0x5A4D)
			goto next_page;

		u32 e_lfanew = intro_read_virt32(vcpu, entrypoint + 0x3C);
		if (e_lfanew <= 0x40 || e_lfanew > 0x200 )
			goto next_page;

		u32 nt_signature = intro_read_virt32(vcpu, entrypoint + e_lfanew);
		if (nt_signature != 0x4550)
			goto next_page;

		u32 image_size = intro_read_virt32(vcpu, entrypoint + e_lfanew + 0x50);
		if (image_size < 0x1000000)
			goto next_page;

		return entrypoint;

	next_page:
		entrypoint -= PAGE_SIZE;
	}

	return 0;
}

void dump_module_list(struct kvm_vcpu* vcpu, gva_t module_list) {
	gva_t current_module = intro_read_virt64(vcpu, module_list);
	if (!current_module)
		return;

	u32 max_incr = 0;
	while ((current_module != module_list) && (max_incr++ < 4096)) {
		struct _LDR_DATA_TABLE_ENTRY table_entry = {0};
		intro_read_virt(vcpu, current_module, &table_entry, sizeof(struct _LDR_DATA_TABLE_ENTRY));

		if (table_entry.DllBase && table_entry.SizeOfImage) {
			char name[256] = { 0 };
			intro_read_wstr(vcpu, &table_entry.BaseDllName, name, sizeof(name));

			printk(KERN_ALERT "[%s] -> [ 0x%llx | 0x%x ]\n", name, table_entry.DllBase, table_entry.SizeOfImage);
		}

		current_module = intro_read_virt64(vcpu, current_module);
		if (!current_module)
			break;
	}
}

void introspection_rdtsc_callback(struct kvm_vcpu *vcpu)  {}
void introspection_rdmsr_callback(struct kvm_vcpu *vcpu) {}
void introspection_xsetbv_callback(struct kvm_vcpu *vcpu) {}

void introspection_cpuid_callback(struct kvm_vcpu *vcpu) {
	struct kvm_host_map map;
	u32 eax = kvm_rax_read(vcpu);
	u64 rip = kvm_rip_read(vcpu);

	switch (eax) {
		case INTROSPECTION_CPUID_INIT: {
			void cb(ZydisDecodedInstruction* instr, const char* text, u64 rip) {
				printk(KERN_ALERT "0x%llx %s\n", rip, text);
			}

			hva_t mapping = intro_map_virt(vcpu, rip, &map);
			if (mapping) {
				intro_disassemble_text(intro_map_virt(vcpu, rip, &map), rip, 0x20, cb);
				intro_unmap(vcpu, &map);
			}

			printk(KERN_ALERT "0x%lx\n", intro_get_ntoskrnl(vcpu));
			break;
		}
		case INTROSPECTION_CPUID_DUMP_MODULES: {
			struct pe_header ntoskrnl_pe;
			gva_t ntoskrnl_va = intro_get_ntoskrnl(vcpu);
			if (intro_init_pe(vcpu, ntoskrnl_va, &ntoskrnl_pe)) {
				unsigned long i;
				struct pe_export* export;

				intro_pe_for_each_export_ref(i, export, ntoskrnl_pe) {
					printk(KERN_ALERT "%s, 0x%lx\n", export->name, export->address);
				}

				struct pe_export* module_list_export = intro_find_export_pe(&ntoskrnl_pe, "PsLoadedModuleList");
				if (module_list_export) {
					printk(KERN_ALERT "%s, 0x%lx\n", module_list_export->name, module_list_export->address);
				}

				dump_module_list(vcpu, module_list_export->address);

				intro_free_pe(&ntoskrnl_pe);
			}

			break;
		}
	}

	// u64 packed = ((u64)ecx) << 32 | edx;
}

void battleye_anti_vm(struct kvm_vcpu* vcpu) {
	u64 r9 = kvm_r9_read(vcpu);
	if (r9 == 0x6590) {
		kvm_r9_write(vcpu, 10);
		return;
	}

	struct kvm_host_map map;
	u64 rip = kvm_rip_read(vcpu);
	hva_t rip_hva = intro_map_virt(vcpu, rip - 0x20, &map);
	if (!rip_hva)
		return;

	u8 vm_check_cmp[7] = {
		// cmp r9d, 0x6590
		0x41, 0x81, 0xF9, 0x90, 0x65, 0x00, 0x00
	};

	for (u64 offset = 0; offset < 0x20; offset++) {
		if (!memcmp((void*)(rip_hva + offset), vm_check_cmp, sizeof(vm_check_cmp))) {
			kvm_r9_write(vcpu, 0x6590);
			kvm_vcpu_unmap(vcpu, &map, true);
			return;
		}
	}

	kvm_vcpu_unmap(vcpu, &map, true);
}

void introspection_vmexit_callback(struct kvm_vcpu* vcpu) {
	battleye_anti_vm(vcpu);
}
