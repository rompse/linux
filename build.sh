make -j16 &&
make modules -j16 &&
sudo make modules_install -j16 &&
sudo cp -v arch/x86_64/boot/bzImage /boot/vmlinuz-swag &&
sudo mkinitcpio -p linux-swag
