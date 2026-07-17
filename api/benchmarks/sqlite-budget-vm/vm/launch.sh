#!/usr/bin/env bash
set -euo pipefail

vm_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
benchmark_dir=$(cd "$vm_dir/.." && pwd)
work_dir=${AUTHOS_VM_WORK_DIR:-$benchmark_dir/.work/vm}
image=${AUTHOS_VM_IMAGE:?set AUTHOS_VM_IMAGE to the Ubuntu cloud image path}
public_key_file=${AUTHOS_VM_PUBLIC_KEY:?set AUTHOS_VM_PUBLIC_KEY to an SSH public-key file}
tap=${AUTHOS_VM_TAP:-tap-authos}
expected_image_sha256=0826c5005ebc70edcfc4519e5d65eca766782f16426231c4c3e92b811ba8df0b

for command in cloud-localds python3 qemu-img qemu-system-x86_64 realpath sha256sum; do
  command -v "$command" >/dev/null || {
    echo "missing required command: $command" >&2
    exit 1
  }
done
[[ -r "$image" ]] || { echo "cloud image is not readable: $image" >&2; exit 1; }
[[ -r "$public_key_file" ]] || { echo "public key is not readable: $public_key_file" >&2; exit 1; }
image=$(realpath "$image")
public_key_file=$(realpath "$public_key_file")
ip link show "$tap" >/dev/null 2>&1 || {
  echo "TAP interface $tap does not exist; create it as documented in README.md" >&2
  exit 1
}

actual_image_sha256=$(sha256sum "$image" | cut -d' ' -f1)
if [[ "$actual_image_sha256" != "$expected_image_sha256" ]]; then
  echo "unexpected Ubuntu image SHA-256: $actual_image_sha256" >&2
  exit 1
fi

install -d -m 700 "$work_dir"
python3 - "$vm_dir/user-data.example" "$work_dir/user-data" "$public_key_file" <<'PY'
from pathlib import Path
import sys

template = Path(sys.argv[1]).read_text(encoding="utf-8")
public_key = Path(sys.argv[3]).read_text(encoding="utf-8").strip()
if not public_key.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-")):
    raise SystemExit("unsupported SSH public-key format")
Path(sys.argv[2]).write_text(
    template.replace("REPLACE_WITH_BENCHMARK_PUBLIC_KEY", public_key),
    encoding="utf-8",
)
PY

rm -f "$work_dir/seed.iso" "$work_dir/authos-vm.qcow2" \
  "$work_dir/qemu.pid" "$work_dir/qemu-monitor.sock" "$work_dir/serial.log"
cloud-localds --network-config="$vm_dir/network-config" \
  "$work_dir/seed.iso" "$work_dir/user-data" "$vm_dir/meta-data"
qemu-img create -q -f qcow2 -F qcow2 -b "$image" \
  "$work_dir/authos-vm.qcow2" 25G

qemu-system-x86_64 \
  -daemonize \
  -name authos-budget-vm \
  -enable-kvm \
  -machine q35,accel=kvm \
  -cpu host \
  -smp 1 \
  -m 1024 \
  -drive if=virtio,file="$work_dir/authos-vm.qcow2",format=qcow2,cache=none,aio=native \
  -drive if=virtio,file="$work_dir/seed.iso",format=raw,readonly=on \
  -netdev tap,id=net0,ifname="$tap",script=no,downscript=no \
  -device virtio-net-pci,netdev=net0,mac=52:54:00:76:00:02 \
  -display none \
  -serial file:"$work_dir/serial.log" \
  -monitor unix:"$work_dir/qemu-monitor.sock",server=on,wait=off \
  -pidfile "$work_dir/qemu.pid"

echo "VM started with PID $(cat "$work_dir/qemu.pid")"
echo "Wait for SSH: ssh benchmark@192.168.76.2"
