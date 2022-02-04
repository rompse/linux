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

struct windows_pe {

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

bool intro_init_win_context(struct windows_context* ctx);
bool intro_init_pe(struct windows_pe* pe, gva_t address);

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

//static u64 g_psloadedmodulelist = 0;

/*char* utf16toutf8_(char* Destination, const u16* Source, u32 DestinationMaxLength)
{
	u32 i;

	for (i = 0; (i < DestinationMaxLength - 1) && (Source[i] != 0); i++)
	{
		Destination[i] = (char)Source[i];
	}

	Destination[i] = 0;

	return Destination;
}*/

//static bool is_in_range_of_module(struct kvm_vcpu* vcpu, const char* name, u64 rip, u64 kbase, u64 psloadedmodulelist)
//{
//	if (!vcpu || !kbase || !psloadedmodulelist) {
//		printk(KERN_ALERT "INVALID ARGS");
//	}
//	struct x86_exception e;
//
//	psloadedmodulelist += kbase;
//
////	printk(KERN_ALERT "psloadedmodulelist: 0x%llx\n", psloadedmodulelist);
//
//	u64 current_module = psloadedmodulelist;
//	u64 count = 0;
//
//	kvm_read_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, current_module, &e), &current_module, sizeof(u64));
//	if (!current_module) {
//		printk(KERN_ALERT "CURRENT_MODULE INVALID");
//	}
//
//	while ((current_module != psloadedmodulelist) && (count++ < 4096))
//	{
//		LDR_DATA_TABLE_ENTRY64 mod_info = {0};
//		kvm_read_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, current_module, &e), &mod_info, sizeof(LDR_DATA_TABLE_ENTRY64));
//
//		if (mod_info.DllBase || mod_info.SizeOfImage) {
//			char arr[256] = { 0 };
//			u32 name_size = mod_info.DriverName.Length & 0xFFFF;
//			u16* name_buffer = kzalloc(name_size + 2ull, GFP_KERNEL_ACCOUNT);
//			kvm_read_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, mod_info.DriverName.Buffer, &e), name_buffer, name_size);
//			utf16toutf8_(arr, name_buffer, sizeof(arr));
//
//			u64 start = mod_info.DllBase;
//			u64 end = mod_info.DllBase + mod_info.SizeOfImage;
//			if (strcmp(arr, name) == 0 && rip >= start && rip <= end)
//				return true;
//
////			printk(KERN_ALERT "DRIVER[%s] -> [ 0x%llx | 0x%x ]\n", arr, mod_info.DllBase, mod_info.SizeOfImage);
//		}
//
//		kvm_read_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, current_module, &e), &current_module, sizeof(u64));
//		if (!current_module) {
//			printk(KERN_ALERT "FAILED GETTING FLINK");
//			break;
//		}
//	}
//
//	return false;
//}
//
//static void dump_module_list_(struct kvm_vcpu* vcpu, u64 kbase, u64 psloadedmodulelist) {
//	if (!vcpu || !kbase || !psloadedmodulelist) {
//		printk(KERN_ALERT "INVALID ARGS");
//	}
//	struct x86_exception e;
//
//	psloadedmodulelist += kbase;
//
//	printk(KERN_ALERT "psloadedmodulelist: 0x%llx\n", psloadedmodulelist);
//
//	u64 current_module = psloadedmodulelist;
//	u64 count = 0;
//
//	kvm_read_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, current_module, &e), &current_module, sizeof(u64));
//	if (!current_module) {
//		printk(KERN_ALERT "CURRENT_MODULE INVALID");
//	}
//
//	while ((current_module != psloadedmodulelist) && (count++ < 4096))
//	{
//		LDR_DATA_TABLE_ENTRY64 mod_info = {0};
//		kvm_read_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, current_module, &e), &mod_info, sizeof(LDR_DATA_TABLE_ENTRY64));
//
//		if (mod_info.DllBase || mod_info.SizeOfImage) {
//			char arr[256] = { 0 };
//			u32 name_size = mod_info.DriverName.Length & 0xFFFF;
//			u16* name_buffer = kzalloc(name_size + 2ull, GFP_KERNEL_ACCOUNT);
//			kvm_read_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, mod_info.DriverName.Buffer, &e), name_buffer, name_size);
//			utf16toutf8_(arr, name_buffer, sizeof(arr));
//
//			printk(KERN_ALERT "DRIVER[%s] -> [ 0x%llx | 0x%x ]\n", arr, mod_info.DllBase, mod_info.SizeOfImage);
//		}
//
//		kvm_read_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, current_module, &e), &current_module, sizeof(u64));
//		if (!current_module) {
//			printk(KERN_ALERT "FAILED GETTING FLINK");
//			break;
//		}
//	}
//}
//
//void disasm_be(struct kvm_vcpu *vcpu, u64 psloadedmodulelist) {
//	static u64 kbase = 0;
//	if (!kbase) {
//		kbase = get_kernel_base_(vcpu, get_kernel_entry(vcpu));
//	}
//
//	struct kvm_host_map map;
//	u64 rip = kvm_rip_read(vcpu);
//	bool in_range = is_in_range_of_module(vcpu, "BEDaisy.sys", rip, kbase, psloadedmodulelist);
//	if (!in_range)
//		return;
//
//	printk(KERN_ALERT "CPUID CALLED FROM BEDAISY\n");
//
//	gpa_t gpa = kvm_mmu_gva_to_gpa_read(vcpu, rip, NULL);
//	if (kvm_vcpu_map(vcpu, gpa_to_gfn(gpa), &map)) {
//		printk(KERN_ALERT "vcpu map fail...\n");
//		return;
//	}
//
//	if (!map.hva) {
//		printk(KERN_ALERT "mapped page invalid hva...\n");
//		return;
//	}
//
//	u8* hva = map.hva + offset_in_page(gpa);
//
//	ZydisDecoder decoder;
//	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
//	ZydisFormatter formatter;
//	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
//	ZyanU64 runtime_address = rip;
//	ZyanUSize offset = 0;
//	const ZyanUSize length = 0x20;
//	ZydisDecodedInstruction instruction;
//	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
//	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, hva + offset, length - offset,
//						   &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE,
//						   ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY)))
//	{
//		char buffer[256];
//		ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
//						instruction.operand_count_visible, buffer, sizeof(buffer), runtime_address);
//		printk(KERN_ALERT "0x%llx %s", runtime_address, buffer);
//
//		offset += instruction.length;
//		runtime_address += instruction.length;
//	}
//
//	kvm_vcpu_unmap(vcpu, &map, true);
//}

void introspection_rdtsc_callback(struct kvm_vcpu *vcpu)  {
//	if (g_psloadedmodulelist)
//		disasm_be(vcpu, g_psloadedmodulelist);
}

//void slide_with_the_heater(struct kvm_vcpu *vcpu) {
//	u64 r9 = kvm_r9_read(vcpu);
//
//	if (r9 == 26000) {
//		struct kvm_host_map map;
//		u64 rip = kvm_rip_read(vcpu);
//		rip -= 0x20;
//		printk(KERN_ALERT "SLIDING DOWN MR. SUTERS BLOCK WITH THE HEATER [ RIP -> 0x%llx ]\n", rip);
//
//		gpa_t gpa = kvm_mmu_gva_to_gpa_read(vcpu, rip, NULL);
//		if (kvm_vcpu_map(vcpu, gpa_to_gfn(gpa), &map)) {
//			printk(KERN_ALERT "vcpu map fail...\n");
//			return;
//		}
//
//		if (!map.hva) {
//			printk(KERN_ALERT "mapped page invalid hva...\n");
//			return;
//		}
//
//		u8* hva = map.hva + offset_in_page(gpa);
//
//		ZydisDecoder decoder;
//		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
//		ZydisFormatter formatter;
//		ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
//		ZyanU64 runtime_address = rip;
//		ZyanUSize offset = 0;
//		const ZyanUSize length = 0x40;
//		ZydisDecodedInstruction instruction;
//		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
//		while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, hva + offset, length - offset,
//							   &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE,
//							   ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY)))
//		{
//			char buffer[256];
//			ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
//							instruction.operand_count_visible, buffer, sizeof(buffer), runtime_address);
//			printk(KERN_ALERT "0x%llx %s", runtime_address, buffer);
//
//			offset += instruction.length;
//			runtime_address += instruction.length;
//		}
//
//		kvm_vcpu_unmap(vcpu, &map, true);
//
//		kvm_r9_write(vcpu, 100);
//	}
//}

void introspection_rdmsr_callback(struct kvm_vcpu *vcpu) {
//	slide_with_the_heater(vcpu);
}

void introspection_xsetbv_callback(struct kvm_vcpu *vcpu) {
//	slide_with_the_heater(vcpu);
}

void introspection_cpuid_callback(struct kvm_vcpu *vcpu) {
	struct kvm_host_map map;
	u32 eax = kvm_rax_read(vcpu);
	u64 rip = kvm_rip_read(vcpu);

	switch (eax) {
		case INTROSPECTION_CPUID_INIT ... INTROSPECTION_CPUID_DUMP_MODULES: {
			void cb(ZydisDecodedInstruction* instr, const char* text, u64 rip) {
				printk(KERN_ALERT "0x%llx %s\n", rip, text);
			}

			hva_t mapping = intro_map_virt(vcpu, rip, &map);
			if (mapping) {
				intro_disassemble_text(intro_map_virt(vcpu, rip, &map), rip, 0x20, cb);
				intro_unmap(vcpu, &map);
			}

			printk(KERN_ALERT "0x%llx\n", intro_get_ntoskrnl(vcpu));
		}
	}

	//	u32 ebx = kvm_rbx_read(vcpu);
	//	u32 ecx = kvm_rcx_read(vcpu);
	//	u32 edx = kvm_rdx_read(vcpu);

//	slide_with_the_heater(vcpu);
//
//	switch (eax) {
//	case INTROSPECTION_CPUID_INIT: {
//		struct kvm_host_map map;
//		u64 rip = kvm_rip_read(vcpu);
//		gpa_t gpa = kvm_mmu_gva_to_gpa_read(vcpu, rip, NULL);
//		if (kvm_vcpu_map(vcpu, gpa_to_gfn(gpa), &map)) {
//			printk(KERN_ALERT "vcpu map fail...\n");
//			return;
//		}
//
//		if (!map.hva) {
//			printk(KERN_ALERT "mapped page invalid hva...\n");
//			return;
//		}
//
//		u8* hva = map.hva + offset_in_page(gpa);
//
//		ZydisDecoder decoder;
//		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
//		ZydisFormatter formatter;
//		ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
//		ZyanU64 runtime_address = rip;
//		ZyanUSize offset = 0;
//		const ZyanUSize length = 0x20;
//		ZydisDecodedInstruction instruction;
//		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
//		while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, hva + offset, length - offset,
//							   &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE,
//							   ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY)))
//		{
//			char buffer[256];
//			ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
//							instruction.operand_count_visible, buffer, sizeof(buffer), runtime_address);
//			printk(KERN_ALERT "0x%llx %s", runtime_address, buffer);
//
//			offset += instruction.length;
//			runtime_address += instruction.length;
//		}
//
//		kvm_vcpu_unmap(vcpu, &map, true);
//
//		break;
//	}
//
//	case INTROSPECTION_CPUID_DUMP_MODULES: {
//		u64 kbase = get_kernel_base_(vcpu, get_kernel_entry(vcpu));
//		u64 packed = ((u64)ecx) << 32 | edx;
//		printk(KERN_ALERT "[kbase] 0x%llx\n", kbase);
//		printk(KERN_ALERT "[psloadedmodulelist] 0x%llx\n", packed);
//		g_psloadedmodulelist = packed;
//		dump_module_list_(vcpu, kbase, packed);
//		break;
//	}
//	}
}

void battleye_anti_vm(struct kvm_vcpu* vcpu) {
	struct kvm_host_map map;
	u64 rip = kvm_rip_read(vcpu);
	u64 r9 = kvm_r9_read(vcpu);

	if (r9 == 0x6590) {
		printk(KERN_ALERT "[0x%llx] r9 == 0x6590, setting r9 to 10...\n", rip);
		kvm_r9_write(vcpu, 10);
	}

	u8 vm_cmp[7] = {
		// cmp r9d, 0x6590
		0x41, 0x81, 0x9, 0x90, 0x65, 0x00, 0x00
	};

	hva_t rip_hva = intro_map_virt(vcpu, rip - 0x20, &map);
	if (!rip_hva)
		return;

	for (u64 offset = 0; offset < 0x20; offset++) {
		if (!memcmp(rip_hva + offset, vm_cmp, sizeof(vm_cmp))) {
			printk(KERN_ALERT "[0x%llx] found cmp, setting r9 to 0x6590...\n", rip);
			kvm_r9_write(vcpu, 0x6590);
		}
	}

	intro_unmap(vcpu, &map);
}

void anti_vm_real(struct kvm_vcpu* vcpu) {
	u64 rip = kvm_rip_read(vcpu) - 0x20;
	u64 r9 = kvm_r9_read(vcpu);

	struct kvm_host_map map;
	gpa_t gpa = kvm_mmu_gva_to_gpa_read(vcpu, rip, NULL);
	if (kvm_vcpu_map(vcpu, gpa_to_gfn(gpa), &map)) {
		printk(KERN_ALERT "vcpu map fail...\n");
		return;
	}

	if (!map.hva) {
		printk(KERN_ALERT "mapped page invalid hva...\n");
		return;
	}

	u8* hva = map.hva + offset_in_page(gpa);

	u8 arr[7] = {0x41, 0x81, 0xF9, 0x90, 0x65, 0x00, 0x00};
	bool sussy = false;
	for (u64 i = 0; i < 0x20; i++) {
		if (!memcmp(hva + i, arr, sizeof(arr))) {
			printk(KERN_ALERT "MR SUTER MATCHED ON CMP [RIP] -> 0x%llx\n", rip);
			kvm_r9_write(vcpu, 0x6590);
			sussy = true;
		}
	}

	if (!sussy && r9 == 0x6590) {
		printk(KERN_ALERT "MR SUTER MATCHED ON R9  [RIP] -> 0x%llx\n", rip);
		kvm_r9_write(vcpu, 10);
	}

	kvm_vcpu_unmap(vcpu, &map, true);
}

void introspection_vmexit_callback(struct kvm_vcpu* vcpu) {
	anti_vm_real(vcpu);
}