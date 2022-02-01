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
#include "x86.h"

#define ZYAN_NO_LIBC
#include <Zydis/Zydis.h>

u64 get_kernel_entry(struct kvm_vcpu* vcpu) {
	u8 buf[ 0x1000 ];

	for ( u32 i = 0; i < 100; i++ ) {
		memset( buf, 0, sizeof( buf ) );

		u64 addr = i * 0x1000;
		struct kvm_host_map map;
		if (kvm_vcpu_map(vcpu, gpa_to_gfn(addr), &map)) {
			continue;
		}

		if (!map.hva) {
			continue;
		}

		memcpy(buf, map.hva, 0x1000);

		kvm_vcpu_unmap(vcpu, &map, true);

		if ( 0x00000001000600E9 ^ ( 0xffffffffffff00ff & *( u64* ) ( buf ) ) ) {
			continue;
		}

		if ( 0xfffff80000000000 ^ ( 0xfffff80000000000 & *( u64* ) ( buf + 0x70 ) ) ) {
			continue;
		}

		if ( 0xffffff0000000fff & *( u64* ) ( buf + 0xa0 ) ) {
			continue;
		}

		return *( u64* ) ( buf + 0x70 );
	}

	return 0;
}

u64 get_kernel_base_(struct kvm_vcpu* vcpu, u64 address) {
	printk(KERN_ALERT "address [0x%llx]\n", address);

	u64 base = 0;
	address &= ~( PAGE_SIZE - 1 );

	for ( u64 size = 0; size < (1024 * 1024) && address > 0; size += 1 ) {
		u16 header = 0;
		struct x86_exception e;
		kvm_read_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, address, &e), &header, sizeof(u16));

		if (header == 0x5A4D) {
			u32 eflaw = 0;
			kvm_read_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, address + 0x3C, &e), &eflaw, sizeof(u32));

			if (eflaw >= 0x40 && eflaw < 0x200 ) {
				u32 sus = 0;
				kvm_read_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, address + eflaw, &e), &sus, sizeof(u32));
				if (sus == 0x4550) {
					u32 size = 0;
					kvm_read_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, address + eflaw + 0x50, &e), &size, sizeof(u32));
					printk(KERN_ALERT "sussy image size -> [0x%llx] 0x%x\n", address, size);

					if (size >= 0x1000000) {
						base = address;
						break;
					}
				}
			}
		}

		address -= PAGE_SIZE;
	}

	return base;
}

typedef struct _UNICODE_STRING64
{
	u16   Length;
	u16   MaximumLength;
	u32  _Rserved1;
	u64  Buffer;
} UNICODE_STRING64;

typedef struct _LIST_ENTRY64
{
	u64 Flink, Blink;
} LIST_ENTRY64, *PLIST_ENTRY64;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64            InLoadOrderLinks;
	LIST_ENTRY64            InMemoryOrderLinks;
	LIST_ENTRY64            InInitializationOrderLinks;
	u64                   DllBase;
	u64                   EntryPoint;
	u64                   SizeOfImage;
	UNICODE_STRING64        DriverPath;
	UNICODE_STRING64        DriverName;
	u32                   Flags;
	u16                    LoadCount;
	u16                    TlsIndex;
	LIST_ENTRY64            HashLinks;
	u64                   SectionPointer;
	u32                   CheckSum;
	u32                   TimeDateStamp;
	u64                   LoadedImports;
	u64                   EntryPointActivationContext;
	u64                   PatchInformation;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

char* utf16toutf8_(char* Destination, const u16* Source, u32 DestinationMaxLength)
{
	u32 i;

	for (i = 0; (i < DestinationMaxLength - 1) && (Source[i] != 0); i++)
	{
		Destination[i] = (char)Source[i];
	}

	Destination[i] = 0;

	return Destination;
}


static bool is_in_range_of_module(struct kvm_vcpu* vcpu, const char* name, u64 rip, u64 kbase, u64 psloadedmodulelist)
{
	if (!vcpu || !kbase || !psloadedmodulelist) {
		printk(KERN_ALERT "INVALID ARGS");
	}
	struct x86_exception e;

	psloadedmodulelist += kbase;

//	printk(KERN_ALERT "psloadedmodulelist: 0x%llx\n", psloadedmodulelist);

	u64 current_module = psloadedmodulelist;
	u64 count = 0;

	kvm_read_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, current_module, &e), &current_module, sizeof(u64));
	if (!current_module) {
		printk(KERN_ALERT "CURRENT_MODULE INVALID");
	}

	while ((current_module != psloadedmodulelist) && (count++ < 4096))
	{
		LDR_DATA_TABLE_ENTRY64 mod_info = {0};
		kvm_read_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, current_module, &e), &mod_info, sizeof(LDR_DATA_TABLE_ENTRY64));

		if (mod_info.DllBase || mod_info.SizeOfImage) {
			char arr[256] = { 0 };
			u32 name_size = mod_info.DriverName.Length & 0xFFFF;
			u16* name_buffer = kzalloc(name_size + 2ull, GFP_KERNEL_ACCOUNT);
			kvm_read_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, mod_info.DriverName.Buffer, &e), name_buffer, name_size);
			utf16toutf8_(arr, name_buffer, sizeof(arr));

			u64 start = mod_info.DllBase;
			u64 end = mod_info.DllBase + mod_info.SizeOfImage;
			if (strcmp(arr, name) == 0 && rip >= start && rip <= end)
				return true;

//			printk(KERN_ALERT "DRIVER[%s] -> [ 0x%llx | 0x%x ]\n", arr, mod_info.DllBase, mod_info.SizeOfImage);
		}

		kvm_read_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, current_module, &e), &current_module, sizeof(u64));
		if (!current_module) {
			printk(KERN_ALERT "FAILED GETTING FLINK");
			break;
		}
	}

	return false;
}

static void dump_module_list_(struct kvm_vcpu* vcpu, u64 kbase, u64 psloadedmodulelist) {
	if (!vcpu || !kbase || !psloadedmodulelist) {
		printk(KERN_ALERT "INVALID ARGS");
	}
	struct x86_exception e;

	psloadedmodulelist += kbase;

	printk(KERN_ALERT "psloadedmodulelist: 0x%llx\n", psloadedmodulelist);

	u64 current_module = psloadedmodulelist;
	u64 count = 0;

	kvm_read_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, current_module, &e), &current_module, sizeof(u64));
	if (!current_module) {
		printk(KERN_ALERT "CURRENT_MODULE INVALID");
	}

	while ((current_module != psloadedmodulelist) && (count++ < 4096))
	{
		LDR_DATA_TABLE_ENTRY64 mod_info = {0};
		kvm_read_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, current_module, &e), &mod_info, sizeof(LDR_DATA_TABLE_ENTRY64));

		if (mod_info.DllBase || mod_info.SizeOfImage) {
			char arr[256] = { 0 };
			u32 name_size = mod_info.DriverName.Length & 0xFFFF;
			u16* name_buffer = kzalloc(name_size + 2ull, GFP_KERNEL_ACCOUNT);
			kvm_read_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, mod_info.DriverName.Buffer, &e), name_buffer, name_size);
			utf16toutf8_(arr, name_buffer, sizeof(arr));

			printk(KERN_ALERT "DRIVER[%s] -> [ 0x%llx | 0x%x ]\n", arr, mod_info.DllBase, mod_info.SizeOfImage);
		}

		kvm_read_guest(vcpu->kvm, kvm_mmu_gva_to_gpa_system(vcpu, current_module, &e), &current_module, sizeof(u64));
		if (!current_module) {
			printk(KERN_ALERT "FAILED GETTING FLINK");
			break;
		}
	}
}

void disasm_be(struct kvm_vcpu *vcpu, u64 psloadedmodulelist) {
	static u64 kbase = 0;
	if (!kbase) {
		kbase=get_kernel_base_(vcpu, get_kernel_entry(vcpu));
	}

	struct kvm_host_map map;
	u64 rip = kvm_rip_read(vcpu);
	rip -= 0x20;
	bool in_range = is_in_range_of_module(vcpu, "BEDaisy.sys", rip, kbase, psloadedmodulelist);
	if (!in_range)
		return;

	printk(KERN_ALERT "CPUID CALLED FROM BEDAISY\n");

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

	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
	ZyanU64 runtime_address = rip;
	ZyanUSize offset = 0;
	const ZyanUSize length = 0x40;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, hva + offset, length - offset,
						   &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE,
						   ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY)))
	{
		char buffer[256];
		ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
						instruction.operand_count_visible, buffer, sizeof(buffer), runtime_address);
		printk(KERN_ALERT "0x%llx %s", runtime_address, buffer);

		offset += instruction.length;
		runtime_address += instruction.length;
	}

	kvm_vcpu_unmap(vcpu, &map, true);
}

void introspection_cpuid_callback(struct kvm_vcpu *vcpu) {
	u32 eax = kvm_rax_read(vcpu);
	u32 ebx = kvm_rbx_read(vcpu);
	u32 ecx = kvm_rcx_read(vcpu);
	u32 edx = kvm_rdx_read(vcpu);

	static u64 psloadedmodulelist = 0;
	if (psloadedmodulelist)
		disasm_be(vcpu, psloadedmodulelist);

	switch (eax) {
	case INTROSPECTION_CPUID_INIT: {
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

		break;
	}

	case INTROSPECTION_CPUID_DUMP_MODULES: {
		u64 kbase = get_kernel_base_(vcpu, get_kernel_entry(vcpu));
		u64 packed = ((u64)ecx) << 32 | edx;
		printk(KERN_ALERT "[kbase] 0x%llx\n", kbase);
		printk(KERN_ALERT "[psloadedmodulelist] 0x%llx\n", packed);
		psloadedmodulelist = packed;
		dump_module_list_(vcpu, kbase, packed);
		break;
	}
	}
}