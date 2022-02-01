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

void introspection_cpuid_callback(struct kvm_vcpu *vcpu) {
	u32 eax = kvm_rax_read(vcpu);
	u32 ebx = kvm_rbx_read(vcpu);
	u32 ecx = kvm_rcx_read(vcpu);
	u32 edx = kvm_rdx_read(vcpu);

	switch (eax) {
	case INTROSPECTION_CPUID_INIT: {
		struct kvm_host_map map;
		u64 rip = kvm_rip_read(vcpu);
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
		const ZyanUSize length = 0x20;
		ZydisDecodedInstruction instruction;
		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
		while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, hva + offset, length - offset,
							   &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE,
							   ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY)))
		{
			// Format & print the binary instruction structure to human readable format
			char buffer[256];
			ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
							instruction.operand_count_visible, buffer, sizeof(buffer), runtime_address);
			printk(KERN_ALERT "0x%llx %s", runtime_address, buffer);

			offset += instruction.length;
			runtime_address += instruction.length;
		}

		kvm_vcpu_unmap(vcpu, &map, true);

		break;
	}

	case INTROSPECTION_CPUID_DUMP_MODULES: {

		break;
	}
	}
}