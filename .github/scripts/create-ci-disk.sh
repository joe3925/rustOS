set -euo pipefail

image="$RUNNER_TEMP/rustos-ci-seed.img"
mount_dir="$RUNNER_TEMP/rustos-ci-mount"
loop_device=""

cleanup() {
  if mountpoint -q "$mount_dir"; then
    sudo umount "$mount_dir"
  fi
  if [[ -n "$loop_device" ]]; then
    sudo losetup --detach "$loop_device"
  fi
}
trap cleanup EXIT

truncate -s 0 "$image"
truncate -s 2G "$image"
sgdisk --new=1:2048:0 --typecode=1:0700 --change-name=1:rustOS "$image"

loop_device="$(sudo losetup --find --show --partscan "$image")"
partition="${loop_device}p1"
for _ in {1..10}; do
  [[ -b "$partition" ]] && break
  sleep 0.2
done
[[ -b "$partition" ]]

sudo mkfs.vfat -F 32 -n RUSTOS "$partition"
mkdir -p "$mount_dir"
sudo mount "$partition" "$mount_dir"
sudo mkdir -p \
  "$mount_dir/system/registry" \
  "$mount_dir/system/toml" \
  "$mount_dir/system/mod"
sync

cleanup
trap - EXIT
