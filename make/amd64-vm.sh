#!/usr/bin/env bash
#
# Full-system amd64 builder VM.
#
# On an arm64 host (e.g. Fedora Asahi) you cannot build amd64 container images
# via in-container user-mode emulation: the host's x86 emulation stack
# (FEX/binfmt-dispatcher/muvm on a 16k-page kernel) needs a 4k microVM and is
# not container-compatible. Instead, this script runs a real amd64 Linux guest
# under `qemu-system-x86_64` (full-system, TCG — no KVM for x86 on arm), where
# the build is fully native, and drives the normal `make image` / push targets
# inside it.
#
# The guest is a Debian cloud image (matching the Containerfile base) with
# podman installed via cloud-init. Built images are streamed back to the host's
# podman storage; pushes go straight to the registry from inside the VM.
#
# State lives under .cache/amd64-vm/ (gitignored). Tunables via env:
#   VM_MEM (MiB, 4096)  VM_CPUS (4)  VM_DISK_SIZE (20G)  VM_SSH_PORT (2222)
#   VM_IMAGE_URL (Debian bookworm genericcloud amd64)
set -e
. make/lib.sh

# Normally exported by the Makefile; default it so the script also works when
# run directly.
RELEASE_IMAGE="${RELEASE_IMAGE:-quay.io/town/rolodex}"

VM_DIR="${VM_DIR:-.cache/amd64-vm}"
VM_MEM="${VM_MEM:-4096}"
VM_CPUS="${VM_CPUS:-4}"
VM_DISK_SIZE="${VM_DISK_SIZE:-20G}"
VM_SSH_PORT="${VM_SSH_PORT:-2222}"
VM_USER="builder"
# Cap parallel cargo jobs inside the VM build to bound peak memory (2 fits a
# 4 GiB guest). Empty = let cargo use all guest cores.
VM_BUILD_JOBS="${VM_BUILD_JOBS:-2}"
VM_IMAGE_URL="${VM_IMAGE_URL:-https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2}"

BASE_IMG="${VM_DIR}/base.qcow2"
DISK_IMG="${VM_DIR}/disk.qcow2"
SEED_ISO="${VM_DIR}/seed.iso"
SSH_KEY="${VM_DIR}/id_ed25519"
PID_FILE="${VM_DIR}/qemu.pid"
CONSOLE_LOG="${VM_DIR}/console.log"

SSH_OPTS=(
  -i "${SSH_KEY}"
  -p "${VM_SSH_PORT}"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
  -o ConnectTimeout=10
)

# Remote ref of the built image (the in-VM build is native amd64, so build.sh
# tags it with the amd64 suffix).
image_ref() {
  echo "${RELEASE_IMAGE}:${IMAGE_TAG:-latest}-amd64"
}

vm_pid() {
  [ -f "${PID_FILE}" ] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null && cat "${PID_FILE}"
}

vm_ssh() {
  ssh "${SSH_OPTS[@]}" "${VM_USER}@127.0.0.1" "$@"
}

ensure_image() {
  mkdir -p "${VM_DIR}"
  if [ ! -f "${BASE_IMG}" ]; then
    step "Downloading amd64 cloud base image"
    substep "${VM_IMAGE_URL}"
    curl -fL --retry 3 -C - -o "${BASE_IMG}.part" "${VM_IMAGE_URL}"
    mv "${BASE_IMG}.part" "${BASE_IMG}"
  fi
  if [ ! -f "${DISK_IMG}" ]; then
    step "Creating VM overlay disk (${VM_DISK_SIZE})"
    qemu-img create -f qcow2 -F qcow2 -b "$(realpath "${BASE_IMG}")" "${DISK_IMG}" "${VM_DISK_SIZE}" >/dev/null
  fi
}

ensure_ssh_key() {
  if [ ! -f "${SSH_KEY}" ]; then
    step "Generating VM SSH key"
    ssh-keygen -t ed25519 -N "" -f "${SSH_KEY}" -C "rolodex-amd64-vm" >/dev/null
  fi
}

write_seed() {
  step "Building cloud-init seed"
  local pubkey
  pubkey="$(cat "${SSH_KEY}.pub")"
  cat >"${VM_DIR}/meta-data" <<EOF
instance-id: rolodex-amd64-builder
local-hostname: rolodex-amd64-builder
EOF
  cat >"${VM_DIR}/user-data" <<EOF
#cloud-config
users:
  - name: ${VM_USER}
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - ${pubkey}
package_update: true
packages:
  - podman
  - rsync
  - make
  - ca-certificates
write_files:
  - path: /etc/containers/registries.conf.d/docker.conf
    content: |
      unqualified-search-registries = ["docker.io"]
runcmd:
  - [ systemctl, enable, --now, podman.socket ]
EOF
  genisoimage -quiet -output "${SEED_ISO}" -volid cidata -joliet -rock \
    "${VM_DIR}/user-data" "${VM_DIR}/meta-data"
}

boot_vm() {
  if vm_pid >/dev/null; then
    substep "VM already running (pid $(vm_pid))"
    return 0
  fi
  step "Booting amd64 VM (qemu-system-x86_64, TCG, ${VM_CPUS} vCPU, ${VM_MEM} MiB)"
  warn "Full-system emulation has no KVM for x86 on arm — expect slow builds."
  qemu-system-x86_64 \
    -machine q35 -cpu max -accel tcg -smp "${VM_CPUS}" -m "${VM_MEM}" \
    -drive "if=virtio,format=qcow2,file=${DISK_IMG}" \
    -drive "if=virtio,format=raw,file=${SEED_ISO},readonly=on" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${VM_SSH_PORT}-:22" \
    -device virtio-net-pci,netdev=net0 \
    -display none -serial "file:${CONSOLE_LOG}" \
    -pidfile "${PID_FILE}" -daemonize
}

wait_for_ssh() {
  step "Waiting for SSH (up to 5 min)"
  local deadline=$(( $(date +%s) + 300 ))
  until vm_ssh true 2>/dev/null; do
    if ! vm_pid >/dev/null; then
      warn "qemu exited unexpectedly; see ${CONSOLE_LOG}"
      return 1
    fi
    if [ "$(date +%s)" -gt "${deadline}" ]; then
      warn "SSH did not come up in time; see ${CONSOLE_LOG}"
      return 1
    fi
    sleep 5
  done
  substep "SSH is up"
}

wait_for_cloud_init() {
  step "Waiting for cloud-init to finish provisioning (installs podman)"
  # cloud-init returns non-zero on "degraded"; we only need it to be done.
  vm_ssh "sudo cloud-init status --wait || true" >/dev/null 2>&1 || true
  if vm_ssh "command -v podman" >/dev/null 2>&1; then
    substep "podman present: $(vm_ssh 'podman --version')"
  else
    warn "podman not found in the VM after cloud-init; check ${CONSOLE_LOG}"
    return 1
  fi
}

sync_repo() {
  step "Syncing repository into the VM"
  vm_ssh "mkdir -p rolodex-dns"
  rsync -a --delete \
    -e "ssh ${SSH_OPTS[*]}" \
    --exclude '.git' --exclude 'target' --exclude '.cache' \
    --exclude 'js/node_modules' --exclude 'go/vendor' \
    ./ "${VM_USER}@127.0.0.1:rolodex-dns/"
}

case "$1" in
  up)
    ensure_image
    ensure_ssh_key
    write_seed
    boot_vm
    wait_for_ssh
    wait_for_cloud_init
    step "amd64 builder VM ready"
    ;;
  down)
    pid="$(vm_pid || true)"
    if [ -n "${pid}" ]; then
      step "Stopping amd64 VM (pid ${pid})"
      kill "${pid}" 2>/dev/null || true
    else
      substep "VM not running"
    fi
    ;;
  destroy)
    "$0" down || true
    step "Removing VM state (${VM_DIR})"
    rm -rf "${VM_DIR}"
    ;;
  status)
    if vm_pid >/dev/null; then
      echo "running (pid $(vm_pid))"
      vm_ssh "uname -m; podman --version" 2>/dev/null || echo "(ssh not ready)"
    else
      echo "stopped"
    fi
    ;;
  ssh)
    shift
    vm_ssh "$@"
    ;;
  sync)
    sync_repo
    ;;
  build)
    "$0" up
    sync_repo
    step "Building amd64 image inside the VM ($(image_ref))"
    vm_ssh "cd rolodex-dns && CARGO_BUILD_JOBS='${VM_BUILD_JOBS}' make image IMAGE_TAG='${IMAGE_TAG}'"
    step "Importing $(image_ref) into host podman"
    vm_ssh "sudo podman save $(image_ref)" | ${SUDO} podman load
    substep "Imported $(image_ref)"
    ;;
  push-rc | push-release)
    "$0" up
    sync_repo
    step "Building and pushing amd64 ($1) from inside the VM"
    # Forward registry credentials so the VM can push directly to the registry.
    vm_ssh "cd rolodex-dns && QUAY_USERNAME='${QUAY_USERNAME}' QUAY_PASSWORD='${QUAY_PASSWORD}' \
      CARGO_BUILD_JOBS='${VM_BUILD_JOBS}' IMAGE_TAG='${IMAGE_TAG}' make $1"
    ;;
  *)
    echo "Usage: $0 {up|down|destroy|status|ssh [cmd]|sync|build|push-rc|push-release}"
    exit 1
    ;;
esac
