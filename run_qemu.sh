#!/bin/bash

# Параметры виртуальной машины
MEMORY="4096"
SMP="4"
SOCKSYZ_PORT="43388"
NETDEV="user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:43279-:22"
IMG_PATH="/home/slava/syzkaller_commit/bullseye.img"
KERNEL_PATH="/home/slava/linux/arch/x86/boot/bzImage"
VM_NAME="VM-0"

# Запуск QEMU с нужными параметрами
qemu-system-x86_64 \
    -m $MEMORY \
    -smp $SMP \
    -chardev socket,id=SOCKSYZ,server=on,wait=off,host=localhost,port=$SOCKSYZ_PORT \
    -mon chardev=SOCKSYZ,mode=control \
    -display none \
    -serial stdio \
    -no-reboot \
    -name $VM_NAME \
    -device virtio-rng-pci \
    -enable-kvm \
    -cpu host,migratable=off \
    -device e1000,netdev=net0 \
    -netdev $NETDEV \
    -hda $IMG_PATH \
    -snapshot \
    -kernel $KERNEL_PATH \
    -append "root=/dev/sda console=ttyS0"
