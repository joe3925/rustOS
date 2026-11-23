set -euo pipefail

sudo apt-get update
sudo apt-get install --no-install-recommends -y qemu-system-arm qemu-efi-aarch64 ipxe-qemu gdisk dosfstools
rustup target add aarch64-unknown-none aarch64-unknown-uefi
qemu-system-aarch64 --version
test -f /usr/share/AAVMF/AAVMF_CODE.fd
printf 'quit\n' | timeout 30s qemu-system-aarch64 \
  -machine virt,gic-version=3,its=on,iommu=smmuv3 \
  -global arm-smmuv3.stage=2 \
  -accel tcg \
  -cpu max \
  -smp 4 \
  -m 128M \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/AAVMF/AAVMF_CODE.fd \
  -display none -serial none -monitor stdio -S
