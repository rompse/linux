if virsh shutdown win11-rdtsc; then
	echo "failed to shutdown..."
	virsh destroy win11-rdtsc
else
	echo "shutdown success..."
fi

sudo make M=arch/x86/kvm &&
sudo make M=arch/x86/kvm modules_install &&
sudo rmmod kvm-intel kvm &&
sudo insmod arch/x86/kvm/kvm.ko &&
sudo insmod arch/x86/kvm/kvm-intel.ko &&
virsh start win11-rdtsc