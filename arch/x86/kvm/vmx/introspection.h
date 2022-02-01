#ifndef __KVM_X86_INTROSPECTION_H
#define __KVM_X86_INTROSPECTION_H

#include <linux/kvm_host.h>

#include <asm/kvm.h>
#include <asm/intel_pt.h>

#include "capabilities.h"
#include "kvm_cache_regs.h"
#include "posted_intr.h"
#include "vmcs.h"
#include "vmx_ops.h"
#include "cpuid.h"

// private: -> intro
// public: -> introspection

enum {
	INTROSPECTION_CPUID_INIT = 0x69420,
	INTROSPECTION_CPUID_DUMP_MODULES = 0x69421
};

void introspection_cpuid_callback(struct kvm_vcpu *vcpu);

#endif /* __KVM_X86_INTROSPECTION_H */