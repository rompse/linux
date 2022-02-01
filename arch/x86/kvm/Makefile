# SPDX-License-Identifier: GPL-2.0

ccflags-y += -I $(srctree)/arch/x86/kvm -I $(srctree)/arch/x86/kvm/zydis
ccflags-$(CONFIG_KVM_WERROR) += -Werror

ifeq ($(CONFIG_FRAME_POINTER),y)
OBJECT_FILES_NON_STANDARD_vmenter.o := y
endif

include $(srctree)/virt/kvm/Makefile.kvm

kvm-y			+= x86.o emulate.o i8259.o irq.o lapic.o \
			   i8254.o ioapic.o irq_comm.o cpuid.o pmu.o mtrr.o \
			   hyperv.o debugfs.o mmu/mmu.o mmu/page_track.o \
			   mmu/spte.o

ifdef CONFIG_HYPERV
kvm-y			+= kvm_onhyperv.o
endif

kvm-$(CONFIG_X86_64) += mmu/tdp_iter.o mmu/tdp_mmu.o
kvm-$(CONFIG_KVM_XEN)	+= xen.o

kvm-intel-y		+= vmx/vmx.o vmx/vmenter.o vmx/pmu_intel.o vmx/vmcs12.o \
			   vmx/evmcs.o vmx/nested.o vmx/posted_intr.o vmx/introspection.o \
			   zydis/Zycore/List.o zydis/Zycore/API/Synchronization.o zydis/Zycore/API/Thread.o zydis/Zycore/API/Memory.o zydis/Zycore/API/Terminal.o zydis/Zycore/API/Process.o zydis/Zycore/Allocator.o zydis/Zycore/String.o zydis/Zycore/Format.o zydis/Zycore/ArgParse.o zydis/Zycore/Bitset.o zydis/Zycore/Zycore.o zydis/Zycore/Vector.o zydis/Zydis/DecoderData.o zydis/Zydis/MetaInfo.o zydis/Zydis/SharedData.o zydis/Zydis/FormatterBuffer.o zydis/Zydis/Register.o zydis/Zydis/FormatterATT.o zydis/Zydis/String.o zydis/Zydis/FormatterIntel.o zydis/Zydis/Decoder.o zydis/Zydis/Zydis.o zydis/Zydis/Encoder.o zydis/Zydis/EncoderData.o zydis/Zydis/Utils.o zydis/Zydis/Formatter.o zydis/Zydis/Mnemonic.o zydis/Zydis/FormatterBase.o
kvm-intel-$(CONFIG_X86_SGX_KVM)	+= vmx/sgx.o

kvm-amd-y		+= svm/svm.o svm/vmenter.o svm/pmu.o svm/nested.o svm/avic.o svm/sev.o

ifdef CONFIG_HYPERV
kvm-amd-y		+= svm/svm_onhyperv.o
endif

obj-$(CONFIG_KVM)	+= kvm.o
obj-$(CONFIG_KVM_INTEL)	+= kvm-intel.o
obj-$(CONFIG_KVM_AMD)	+= kvm-amd.o
