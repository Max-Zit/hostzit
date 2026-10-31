#!/bin/sh
# Makes the HostZit appliance VM images on a Proxmox VE host: installs the
# image installer (build-iso.sh with IMAGE=1) into a temporary VM, then
# converts its disk:
#   hostzit-appliance-X.ova    VMware ESXi / Workstation, VirtualBox
#   hostzit-appliance-X.qcow2  Proxmox VE, KVM
#   hostzit-appliance-X.vhdx   Hyper-V (generation 1)
# and the installer ISO hostzit-appliance-X.iso; publish-images.sh
# uploads them to the GitHub release.
#
#   ./build-images.sh hostzit_X_amd64.deb
#
# Environment: VMID (10090), STORAGE (local-lvm), BRIDGE (vmbr0), OUTDIR (.).
set -eu

pkg=$(readlink -f "${1:?usage: build-images.sh hostzit_X_amd64.deb}")
ver=$(basename "$pkg" | sed -n 's/^hostzit_\([0-9.]*\)_.*/\1/p')
src=$(cd "$(dirname "$0")" && pwd)
[ -x "$src/vmdkstream" ] || { echo "missing $src/vmdkstream (GOOS=linux go build -o packaging/appliance/vmdkstream ./tools/vmdkstream)" >&2; exit 1; }
vmid=${VMID:-10090}
storage=${STORAGE:-local-lvm}
bridge=${BRIDGE:-vmbr0}
outdir=$(readlink -f "${OUTDIR:-.}")
base=hostzit-appliance-$ver
iso=/var/lib/vz/template/iso/hostzit-image-installer-$ver.iso
gb=32

finish() {
    qm stop "$vmid" >/dev/null 2>&1 || true
    qm destroy "$vmid" --purge >/dev/null 2>&1 || true
    rm -f "$iso"
}
trap finish EXIT

# 1. Install into a VM; the installer powers it off when it is done.
IMAGE=1 OUT="$iso" "$src/build-iso.sh" "$pkg" >/dev/null
qm create "$vmid" --name hz-image-build --ostype l26 --memory 3072 --cores 2 --net0 "virtio,bridge=$bridge" \
    --scsihw virtio-scsi-pci --scsi0 "$storage:$gb" --ide2 "local:iso/$(basename "$iso"),media=cdrom" --boot 'order=scsi0;ide2' >/dev/null
qm start "$vmid"
echo "installing into VM $vmid ..."
waited=0
until [ "$(qm status "$vmid" | awk '{print $2}')" = stopped ]; do
    [ $waited -lt 3600 ] || { echo "the installation did not finish within an hour" >&2; exit 1; }
    sleep 10
    waited=$((waited + 10))
done

# 2. Convert the disk.
disk=$(pvesm path "$(qm config "$vmid" | sed -n 's/^scsi0: \([^,]*\).*/\1/p')")
cd "$outdir"
qemu-img convert -c -O qcow2 "$disk" "$base.qcow2"
qemu-img convert -O vhdx -o subformat=dynamic "$disk" "$base.vhdx"
# Not qemu-img: its stream-optimized VMDKs lack the trailing grain tables,
# directory and footer, and VMware Workstation rejects them ("SHA digest
# ... does not match manifest"). vmdkstream is built from tools/vmdkstream
# (GOOS=linux go build -o packaging/appliance/vmdkstream ./tools/vmdkstream)
# and checks its result like VMware reads it.
"$src/vmdkstream" -adapter lsilogic "$disk" "$base-disk1.vmdk"
[ "$("$src/vmdkstream" -verify "$base-disk1.vmdk")" = "$(sha256sum < "$disk" | cut -d" " -f1)" ] ||
    { echo "the VMDK does not hold the same disk" >&2; exit 1; }

# 3. The OVA: an OVF descriptor (first), its manifest and the disk.
vmdk_size=$(stat -c %s "$base-disk1.vmdk")
capacity=$((gb * 1073741824))
# item writes one virtual hardware item. The rasd elements must come in the
# schema's (alphabetical) order, or ESXi refuses the OVF.
item() { # id type name extra-lines
    printf '      <Item>\n'
    printf '        <rasd:ElementName>%s</rasd:ElementName>\n        <rasd:InstanceID>%s</rasd:InstanceID>\n        <rasd:ResourceType>%s</rasd:ResourceType>\n%s' "$3" "$1" "$2" "$4" | LC_ALL=C sort
    printf '      </Item>\n'
}
{
    cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
  xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
  xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
  xmlns:vmw="http://www.vmware.com/schema/ovf">
  <References><File ovf:href="$base-disk1.vmdk" ovf:id="file1" ovf:size="$vmdk_size"/></References>
  <DiskSection>
    <Info>Virtual disks</Info>
    <Disk ovf:capacity="$capacity" ovf:capacityAllocationUnits="byte" ovf:diskId="vmdisk1" ovf:fileRef="file1"
      ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <NetworkSection>
    <Info>Networks</Info>
    <Network ovf:name="VM Network"><Description>The network of the websites and the panels</Description></Network>
  </NetworkSection>
  <VirtualSystem ovf:id="$base">
    <Info>HostZit web hosting appliance $ver</Info>
    <Name>HostZit</Name>
    <AnnotationSection>
      <Info>Description</Info>
      <Annotation>HostZit $ver. The panel addresses and the setup token are shown on the screen of the VM after the first start (a few minutes).</Annotation>
    </AnnotationSection>
    <OperatingSystemSection ovf:id="96" vmw:osType="debian12_64Guest"><Info>Debian Linux (64-bit)</Info></OperatingSystemSection>
    <VirtualHardwareSection>
      <Info>Virtual hardware</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemIdentifier>HostZit</vssd:VirtualSystemIdentifier>
        <vssd:VirtualSystemType>vmx-14</vssd:VirtualSystemType>
      </System>
EOF
    item 1 3 "2 virtual CPUs" "        <rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>
        <rasd:VirtualQuantity>2</rasd:VirtualQuantity>
"
    item 2 4 "4096 MB of memory" "        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
        <rasd:VirtualQuantity>4096</rasd:VirtualQuantity>
"
    item 3 6 "SCSI controller 0" "        <rasd:Address>0</rasd:Address>
        <rasd:ResourceSubType>lsilogic</rasd:ResourceSubType>
"
    item 4 17 "Hard disk 1" "        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource>
        <rasd:Parent>3</rasd:Parent>
"
    item 5 10 "Network adapter 1" "        <rasd:AddressOnParent>7</rasd:AddressOnParent>
        <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
        <rasd:Connection>VM Network</rasd:Connection>
        <rasd:ResourceSubType>VmxNet3</rasd:ResourceSubType>
"
    printf '    </VirtualHardwareSection>\n  </VirtualSystem>\n</Envelope>\n'
} > "$base.ovf"
printf 'SHA256(%s)= %s\nSHA256(%s)= %s\n' "$base.ovf" "$(sha256sum "$base.ovf" | cut -d' ' -f1)" \
    "$base-disk1.vmdk" "$(sha256sum "$base-disk1.vmdk" | cut -d' ' -f1)" > "$base.mf"
tar --format=ustar -cf "$base.ova" "$base.ovf" "$base.mf" "$base-disk1.vmdk"
rm -f "$base.ovf" "$base.mf" "$base-disk1.vmdk"
# 4. The installer ISO for new VMs and physical servers.
OUT="$outdir/$base.iso" "$src/build-iso.sh" "$pkg" >/dev/null
sha256sum "$base.iso" "$base.ova" "$base.qcow2" "$base.vhdx" > "$base.SHA256SUMS"
ls -l "$base".*
