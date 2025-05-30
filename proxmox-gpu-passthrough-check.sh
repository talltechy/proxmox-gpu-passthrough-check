#!/bin/bash
# Proxmox GPU Passthrough Readiness Check Script
# Version: 2.2
# Description: Checks for common GPU passthrough prerequisites on a Proxmox VE host
# License: MIT

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Initialize variables
VERBOSE=false
CHECK_HOST=true
CHECK_IOMMU_KERNEL=false
CHECK_IOMMU_DMESG=false
CHECK_VFIO=false
CHECK_IOMMU_GROUPS=false
CHECK_GPU=false
CHECK_CPU_VIRT=false
CHECK_SECURE_BOOT=false
CHECK_BLACKLIST=false
CHECK_GPU_USAGE=false
CHECK_VM=false
CHECK_ALL_VMS=false
VM_ID=""
GENERATE_FIX=false
SHOW_SUMMARY=true
SKIP_HOST_CHECKS=false
SKIP_RUNTIME_CHECKS=false
SCRIPT_START_TIME=$(date +%s.%N)

# Initialize summary arrays
SUCCESS_CHECKS=()
WARNING_CHECKS=()
INFO_CHECKS=()

# Function to print usage
print_usage() {
    echo -e "${BOLD}Usage:${NC} $0 [options]"
    echo -e "${BOLD}Options:${NC}"
    echo "  -h, --help          Show this help message"
    echo "  -v, --verbose       Enable verbose output"
    echo "  -k, --kernel        Check IOMMU in kernel command line only"
    echo "  -d, --dmesg         Check IOMMU in dmesg only"
    echo "  -m, --modules       Check VFIO modules only"
    echo "  -g, --groups        List IOMMU groups only"
    echo "  -p, --gpu           List GPU devices only"
    echo "  -c, --cpu           Check CPU virtualization support only"
    echo "  -s, --secure-boot   Check Secure Boot status only"
    echo "  -b, --blacklist     Check GPU driver blacklisting only"
    echo "  -u, --gpu-usage     Check if GPU is in use by the host only"
    echo "  --vm VMID           Check if the specified VM is properly configured for GPU passthrough"
    echo "  --all-vms           Check all VMs for GPU passthrough configuration"
    echo "  --host-only         Only run host checks, skip VM checks"
    echo "  --skip-host         Skip host checks, only run VM checks"
    echo "  --skip-runtime      Skip runtime checks for running VMs"
    echo "  --generate-fix      Generate commands to fix detected issues (does not execute them)"
    echo "  --no-summary        Don't show summary at the end"
    echo "  --all               Run all host checks (default)"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  $0                  Run all host checks"
    echo "  $0 -v               Run all checks with verbose output"
    echo "  $0 -k -d            Check IOMMU in kernel and dmesg only"
    echo "  $0 -g -p            List IOMMU groups and GPU devices only"
    echo "  $0 --vm 100         Check VM 100 configuration (includes host checks)"
    echo "  $0 --vm 100 --skip-host  Check VM 100 configuration without host checks"
    echo "  $0 --all --vm 100   Run all host checks and check VM 100 configuration"
    echo "  $0 --all-vms        Check all VMs for GPU passthrough configuration"
    echo "  $0 --generate-fix   Generate commands to fix detected issues"
    echo ""
    echo -e "${BOLD}One-line execution:${NC}"
    echo "  curl -s https://raw.githubusercontent.com/talltechy/proxmox-gpu-passthrough-check/main/proxmox-gpu-passthrough-check.sh | bash"
    echo "  or"
    echo "  wget -qO- https://raw.githubusercontent.com/talltechy/proxmox-gpu-passthrough-check/main/proxmox-gpu-passthrough-check.sh | bash"
}

# Function to print section header
print_header() {
    echo -e "\n${BOLD}${BLUE}--- $1 ---${NC}"
}

# Function to print success message
print_success() {
    echo -e "   ${GREEN}SUCCESS:${NC} $1"
    if [ "$SHOW_SUMMARY" = true ]; then
        SUCCESS_CHECKS+=("$1")
    fi
}

# Function to print warning message
print_warning() {
    echo -e "   ${YELLOW}WARNING:${NC} $1"
    if [ "$SHOW_SUMMARY" = true ]; then
        WARNING_CHECKS+=("$1")
    fi
}

# Function to print info message
print_info() {
    echo -e "   ${CYAN}INFO:${NC} $1"
    if [ "$SHOW_SUMMARY" = true ]; then
        INFO_CHECKS+=("$1")
    fi
}

# Function to print error message and exit
print_error() {
    echo -e "${RED}ERROR:${NC} $1" >&2
    exit 1
}

# Function to check if running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        print_warning "This script is not running as root. Some checks may not provide complete information."
        echo "            => Consider running with sudo for full access to system information."
        echo ""
    fi
}

# Function to check for required commands
check_dependencies() {
    local missing_deps=()
    
    for cmd in grep sed lsmod lspci dmesg; do
        if ! command -v $cmd &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_warning "Missing required dependencies: ${missing_deps[*]}"
        echo "            => Install them using: apt-get install ${missing_deps[*]}"
        echo ""
        return 1
    fi
    
    return 0
}

# Function to detect CPU vendor
check_cpu_vendor() {
    if grep -q "vendor_id.*AMD" /proc/cpuinfo; then
        echo "AMD"
    elif grep -q "vendor_id.*Intel" /proc/cpuinfo; then
        echo "Intel"
    else
        echo "Unknown"
    fi
}

# Function to check IOMMU in kernel command line
check_iommu_kernel() {
    print_header "1. Checking Kernel Command Line for IOMMU"
    
    # Detect CPU vendor
    CPU_VENDOR=$(check_cpu_vendor)
    IOMMU_MISSING=false
    
    if grep -q -E 'intel_iommu=on|amd_iommu=on' /proc/cmdline; then
        print_success "'intel_iommu=on' or 'amd_iommu=on' found in kernel command line:"
        grep -oE 'intel_iommu=on|amd_iommu=on' /proc/cmdline | sed 's/^/     /'
        
        # Check for iommu=pt which can improve performance
        if grep -q 'iommu=pt' /proc/cmdline; then
            print_info "'iommu=pt' is enabled, which can improve performance."
        else
            print_info "Consider adding 'iommu=pt' to kernel parameters for better performance."
        fi
    else
        IOMMU_MISSING=true
        print_warning "'intel_iommu=on' or 'amd_iommu=on' NOT found in /proc/cmdline."
        echo "            => For Proxmox VE (Debian-based), run these commands as root:"
        echo "               1. Edit GRUB: nano /etc/default/grub"
        echo "               2. Find the GRUB_CMDLINE_LINUX_DEFAULT line"
        if [ "$CPU_VENDOR" = "AMD" ]; then
            echo "               3. Add 'amd_iommu=on iommu=pt' to the parameters"
        elif [ "$CPU_VENDOR" = "Intel" ]; then
            echo "               3. Add 'intel_iommu=on iommu=pt' to the parameters"
        else
            echo "               3. Add 'intel_iommu=on' (Intel CPU) or 'amd_iommu=on' (AMD CPU) to the parameters"
        fi
        echo "               4. Save and exit (Ctrl+O, Enter, Ctrl+X)"
        echo "               5. Run: update-grub"
        echo "               6. Reboot: reboot"
    fi
    
    echo ""
}

# Function to check IOMMU in dmesg
check_iommu_dmesg() {
    print_header "2. Checking dmesg for IOMMU/DMAR Initialization"
    
    # For Intel
    INTEL_IOMMU_CHECK=$(dmesg | grep -iE 'DMAR: IOMMU enabled|VT-d.*Enabled|DMAR-IR: Enabled')
    # For AMD
    AMD_IOMMU_CHECK=$(dmesg | grep -iE 'AMD-Vi: Enabled|AMD IOMMU.*initialization.*succeeded|AMD IOMMU.*detected')
    # Check for errors
    IOMMU_ERRORS=$(dmesg | grep -iE 'DMAR:.*fault|IOMMU.*error|AMD-Vi:.*error|DMAR:.*failed|AMD-Vi:.*failed')

    if [ -n "$INTEL_IOMMU_CHECK" ] || [ -n "$AMD_IOMMU_CHECK" ]; then
        print_success "Found positive IOMMU/DMAR enabled messages in dmesg:"
        if [ -n "$INTEL_IOMMU_CHECK" ]; then
            echo "$INTEL_IOMMU_CHECK" | sed 's/^/     /'
        fi
        if [ -n "$AMD_IOMMU_CHECK" ]; then
            echo "$AMD_IOMMU_CHECK" | sed 's/^/     /'
        fi
        echo "            => Review these messages. 'Enabled', 'Detected', or 'Succeeded' is good."
    else
        print_warning "Could not find strong confirmation of IOMMU enabled in dmesg."
        echo "            => Manually check 'dmesg | grep -iE \"iommu|dmar|amd-vi|vt-d\"'."
        echo "               Look for errors or messages indicating it's not active or not found."
        echo "            => This could also mean IOMMU (Intel VT-d or AMD-Vi) is not enabled in BIOS/UEFI."
        
        # Detect CPU vendor and provide specific advice
        CPU_VENDOR=$(check_cpu_vendor)
        if [ "$CPU_VENDOR" = "AMD" ]; then
            echo "            => For AMD systems, ensure 'IOMMU' or 'AMD-Vi' is enabled in BIOS/UEFI"
            echo "               and 'amd_iommu=on' is added to kernel parameters."
        elif [ "$CPU_VENDOR" = "Intel" ]; then
            echo "            => For Intel systems, ensure 'VT-d' is enabled in BIOS/UEFI"
            echo "               and 'intel_iommu=on' is added to kernel parameters."
        fi
    fi
    
    if [ -n "$IOMMU_ERRORS" ] && [ "$VERBOSE" = true ]; then
        print_warning "Found IOMMU/DMAR error messages in dmesg:"
        echo "$IOMMU_ERRORS" | sed 's/^/     /'
        echo "            => These errors might indicate issues with IOMMU functionality."
    fi
    
    echo ""
}

# Function to check VFIO modules
check_vfio_modules() {
    print_header "3. Checking for loaded VFIO modules"
    
    MODULES_TO_CHECK=("vfio_pci" "vfio_iommu_type1" "vfio")
    ALL_MODULES_LOADED=true
    MISSING_MODULES=()

    for module in "${MODULES_TO_CHECK[@]}"; do
        if lsmod | grep -q "^\\<$module\\>"; then # Use word boundary
            print_success "'$module' module is loaded."
        else
            print_warning "'$module' module is NOT loaded."
            ALL_MODULES_LOADED=false
            MISSING_MODULES+=("$module")
        fi
    done

    if [ "$ALL_MODULES_LOADED" = false ]; then
        echo "            => To load them, add to /etc/modules: "
        for module in "${MISSING_MODULES[@]}"; do
            echo "               $module"
        done
        echo "            => Then update initramfs (e.g., 'update-initramfs -u -k all') and reboot."
        echo "            => Or load them manually for current session (not persistent): 'modprobe <module_name>'"
    fi
    
    # Check if vfio is configured in initramfs
    if [ -f /etc/initramfs-tools/modules ]; then
        VFIO_IN_INITRAMFS=$(grep -E "vfio|vfio_iommu_type1|vfio_pci" /etc/initramfs-tools/modules)
        if [ -n "$VFIO_IN_INITRAMFS" ] && [ "$VERBOSE" = true ]; then
            print_info "VFIO modules found in initramfs configuration:"
            echo "$VFIO_IN_INITRAMFS" | sed 's/^/     /'
        elif [ -z "$VFIO_IN_INITRAMFS" ] && [ "$VERBOSE" = true ]; then
            print_info "VFIO modules not found in initramfs configuration."
            echo "            => Consider adding them to /etc/initramfs-tools/modules for early loading."
        fi
    fi
    
    echo ""
}

# Function to list IOMMU groups
list_iommu_groups() {
    print_header "4. Listing IOMMU Groups"
    
    print_info "Review these groups. Your target GPU and its related functions (Audio, USB-C)"
    echo "         should ideally be in their own group(s) or with other passthrough-safe devices."
    echo "         Avoid groups containing critical host hardware (like host NICs, USB controllers needed by host, etc.)."
    echo "         If your GPU is in a group with other devices you don't want to pass, you might need an ACS override patch (use with caution)."
    echo ""

    if [ -d "/sys/kernel/iommu_groups" ]; then
        if [ -n "$(ls -A /sys/kernel/iommu_groups)" ]; then
            # Count total groups for progress indication
            TOTAL_GROUPS=$(find /sys/kernel/iommu_groups -mindepth 1 -maxdepth 1 -type d | wc -l)
            CURRENT_GROUP=0
            
            # Find groups with VGA/GPU devices for highlighting
            GPU_GROUPS=()
            if [ "$VERBOSE" = true ]; then
                for iommu_group_dir in /sys/kernel/iommu_groups/*; do
                    group_num=$(basename "$iommu_group_dir")
                    for device_link in "$iommu_group_dir"/devices/*; do
                        device_id=$(readlink -f "$device_link" | xargs basename)
                        if lspci -nns "$device_id" | grep -qE "VGA|3D|Display"; then
                            GPU_GROUPS+=("$group_num")
                            break
                        fi
                    done
                done
            fi
            
            for iommu_group_dir in /sys/kernel/iommu_groups/*; do
                group_num=$(basename "$iommu_group_dir")
                ((CURRENT_GROUP++))
                
                # Check if this group contains a GPU
                GROUP_HAS_GPU=false
                if [[ " ${GPU_GROUPS[*]} " =~ " ${group_num} " ]]; then
                    GROUP_HAS_GPU=true
                fi
                
                if [ "$GROUP_HAS_GPU" = true ]; then
                    echo -e "   ${BOLD}${GREEN}IOMMU Group $group_num:${NC} ${CYAN}(Contains GPU)${NC}"
                else
                    echo -e "   ${BOLD}IOMMU Group $group_num:${NC}"
                fi
                
                for device_link in "$iommu_group_dir"/devices/*; do
                    device_id=$(readlink -f "$device_link" | xargs basename)
                    lspci_output=$(lspci -nns "$device_id")
                    
                    # Highlight GPU devices
                    if echo "$lspci_output" | grep -qE "VGA|3D|Display"; then
                        echo -e "${GREEN}$lspci_output${NC}" | sed 's/^/     /'
                    else
                        echo "$lspci_output" | sed 's/^/     /'
                    fi
                done
                
                # Show progress if verbose and many groups
                if [ "$VERBOSE" = true ] && [ $TOTAL_GROUPS -gt 20 ]; then
                    printf "   Progress: %d/%d groups processed\r" $CURRENT_GROUP $TOTAL_GROUPS
                fi
            done
            
            # Clear progress line
            if [ "$VERBOSE" = true ] && [ $TOTAL_GROUPS -gt 20 ]; then
                printf "                                        \r"
            fi
            
            # Print summary of groups
            print_info "Found $TOTAL_GROUPS IOMMU groups in total."
            if [ ${#GPU_GROUPS[@]} -gt 0 ]; then
                print_info "GPUs found in IOMMU groups: ${GPU_GROUPS[*]}"
            fi
        else
            print_warning "IOMMU groups directory exists but is empty. This might indicate IOMMU is not properly enabled or no devices are isolated."
        fi
    else
        print_warning "/sys/kernel/iommu_groups directory not found. IOMMU may not be enabled or supported."
    fi
    
    echo ""
}

# Function to list GPU devices
list_gpu_devices() {
    print_header "5. Listing VGA/3D/Display Controllers (GPUs)"
    
    print_info "Identify your target GPU's PCI IDs (e.g., 0b:00.0) and current kernel driver."
    echo "         If a host driver (like 'nouveau', 'amdgpu', or 'nvidia') is using the GPU you want to passthrough,"
    echo "         you'll need to blacklist that driver and ensure 'vfio-pci' binds to the GPU at boot."
    echo ""

    GPU_DEVICES=$(lspci -nnk | grep -E 'VGA compatible controller|3D controller|Display controller' -A3 | grep -E '^[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f]|Subsystem:|Kernel driver in use:|Kernel modules:')

    if [ -n "$GPU_DEVICES" ]; then
        # Process and format the output for better readability
        current_device=""
        echo "$GPU_DEVICES" | while IFS= read -r line; do
            if [[ $line =~ ^[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f] ]]; then
                # This is a device line
                current_device=$line
                echo -e "   ${BOLD}${line}${NC}"
            elif [[ $line =~ "Kernel driver in use:" ]]; then
                # Extract and highlight the driver
                driver=$(echo "$line" | sed -E 's/.*Kernel driver in use: (.*)/\1/')
                if [[ "$driver" == "vfio-pci" ]]; then
                    echo -e "   ${line/vfio-pci/${GREEN}vfio-pci${NC}}"
                elif [[ "$driver" == "nvidia" || "$driver" == "amdgpu" || "$driver" == "nouveau" || "$driver" == "radeon" || "$driver" == "i915" ]]; then
                    echo -e "   ${line/$driver/${YELLOW}$driver${NC}} (needs blacklisting for passthrough)"
                else
                    echo "   $line"
                fi
            else
                echo "   $line"
            fi
        done
    else
        print_info "No VGA, 3D, or Display controllers found with lspci."
    fi
    
    echo ""
}

# Function to check CPU virtualization support
check_cpu_virtualization() {
    print_header "6. Checking CPU Virtualization Support"
    
    # Check for Intel VT-x or AMD-V
    if grep -q -E 'vmx|svm' /proc/cpuinfo; then
        if grep -q 'vmx' /proc/cpuinfo; then
            print_success "Intel VT-x virtualization is supported by your CPU."
        fi
        if grep -q 'svm' /proc/cpuinfo; then
            print_success "AMD-V virtualization is supported by your CPU."
        fi
    else
        print_warning "CPU virtualization (Intel VT-x or AMD-V) not found in /proc/cpuinfo."
        echo "            => Ensure virtualization is enabled in BIOS/UEFI settings."
    fi
    
    # Check if virtualization is enabled in KVM
    if [ -e /dev/kvm ]; then
        print_success "KVM virtualization is enabled (/dev/kvm exists)."
    else
        print_warning "KVM virtualization may not be enabled (/dev/kvm does not exist)."
        echo "            => Check if 'kvm_intel' or 'kvm_amd' modules are loaded with 'lsmod | grep kvm'."
    fi
    
    # Check for nested virtualization (optional, for VMs within VMs)
    if [ -f /sys/module/kvm_intel/parameters/nested ] && [ "$(cat /sys/module/kvm_intel/parameters/nested)" = "Y" ]; then
        print_info "Nested virtualization is enabled for Intel."
    elif [ -f /sys/module/kvm_amd/parameters/nested ] && [ "$(cat /sys/module/kvm_amd/parameters/nested)" = "1" ]; then
        print_info "Nested virtualization is enabled for AMD."
    elif [ "$VERBOSE" = true ]; then
        print_info "Nested virtualization status could not be determined or is disabled."
        echo "            => This is only relevant if you want to run VMs inside your VMs."
    fi
    
    echo ""
}

# Function to check Secure Boot status
check_secure_boot() {
    print_header "7. Checking Secure Boot Status"
    
    if command -v mokutil &> /dev/null; then
        SECURE_BOOT_STATUS=$(mokutil --sb-state 2>/dev/null)
        if echo "$SECURE_BOOT_STATUS" | grep -q "SecureBoot enabled"; then
            print_warning "Secure Boot is ENABLED. This may interfere with loading unsigned kernel modules like vfio."
            echo "            => Consider disabling Secure Boot in BIOS/UEFI settings."
            echo "            => Alternatively, you can sign the vfio modules using your own keys."
        elif echo "$SECURE_BOOT_STATUS" | grep -q "SecureBoot disabled"; then
            print_success "Secure Boot is DISABLED. This is good for GPU passthrough."
        else
            print_info "Secure Boot status could not be determined using mokutil."
        fi
    else
        # Try alternative method
        if [ -d /sys/firmware/efi ]; then
            if [ -f /sys/firmware/efi/efivars/SecureBoot-* ]; then
                # Get the last byte of the SecureBoot variable
                SECURE_BOOT_VAR=$(od -An -t u1 /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | awk 'END{print $NF}')
                if [ "$SECURE_BOOT_VAR" = "1" ]; then
                    print_warning "Secure Boot appears to be ENABLED. This may interfere with loading unsigned kernel modules like vfio."
                    echo "            => Consider disabling Secure Boot in BIOS/UEFI settings."
                elif [ "$SECURE_BOOT_VAR" = "0" ]; then
                    print_success "Secure Boot appears to be DISABLED. This is good for GPU passthrough."
                else
                    print_info "Secure Boot status could not be determined."
                fi
            else
                print_info "System is booted in EFI mode, but SecureBoot status could not be determined."
            fi
        else
            print_info "System is not booted in EFI mode, so Secure Boot is not applicable."
        fi
    fi
    
    echo ""
}

# Function to check GPU driver blacklisting
check_gpu_driver_blacklist() {
    print_header "8. Checking GPU Driver Blacklisting"
    
    BLACKLIST_FILES=(/etc/modprobe.d/*blacklist*.conf /etc/modprobe.d/*vfio*.conf)
    BLACKLIST_FOUND=false
    
    print_info "Checking for blacklisted GPU drivers in modprobe configuration files."
    echo "         Blacklisting prevents the host GPU driver from binding to the GPU you want to pass through."
    echo ""
    
    for file in "${BLACKLIST_FILES[@]}"; do
        if [ -f "$file" ]; then
            BLACKLIST_CONTENT=$(grep -E "blacklist (nouveau|nvidia|amdgpu|radeon|i915)" "$file" 2>/dev/null)
            if [ -n "$BLACKLIST_CONTENT" ]; then
                print_success "Found GPU driver blacklist entries in $file:"
                echo "$BLACKLIST_CONTENT" | sed 's/^/     /'
                BLACKLIST_FOUND=true
            fi
            
            VFIO_CONTENT=$(grep -E "options vfio-pci ids=" "$file" 2>/dev/null)
            if [ -n "$VFIO_CONTENT" ]; then
                print_success "Found VFIO PCI ID configuration in $file:"
                echo "$VFIO_CONTENT" | sed 's/^/     /'
                BLACKLIST_FOUND=true
            fi
        fi
    done
    
    if [ "$BLACKLIST_FOUND" = false ]; then
        print_warning "No GPU driver blacklist or VFIO PCI ID configuration found."
        echo "            => You may need to blacklist your GPU driver and configure VFIO-PCI to bind to your GPU."
        echo "            => Create a file like /etc/modprobe.d/vfio.conf with:"
        echo "               blacklist nouveau    # For NVIDIA GPUs with open source driver"
        echo "               blacklist nvidia     # For NVIDIA GPUs with proprietary driver"
        echo "               blacklist amdgpu     # For modern AMD GPUs"
        echo "               blacklist radeon     # For older AMD GPUs"
        echo "               options vfio-pci ids=XXXX:XXXX,XXXX:XXXX  # Your GPU and audio device IDs"
    fi
    
    echo ""
}

# Function to check if GPU is in use by the host
check_gpu_usage() {
    print_header "9. Checking if GPUs are in use by the host"
    
    print_info "Checking for processes using GPUs. A GPU in use by the host cannot be passed to a VM."
    echo ""
    
    # Get list of GPU PCI addresses
    GPU_ADDRESSES=$(lspci -nn | grep -E 'VGA|3D|Display' | cut -d' ' -f1)
    
    if [ -z "$GPU_ADDRESSES" ]; then
        print_info "No GPUs detected."
        return
    fi
    
    GPU_IN_USE=false
    
    for addr in $GPU_ADDRESSES; do
        # Convert address format from 01:00.0 to 0000:01:00.0 as used in /sys
        SYS_ADDR="0000:$addr"
        
        # Check if any process is using this GPU
        if [ -d "/sys/bus/pci/devices/$SYS_ADDR/driver" ]; then
            DRIVER=$(readlink -f "/sys/bus/pci/devices/$SYS_ADDR/driver" | xargs basename)
            
            if [ "$DRIVER" != "vfio-pci" ]; then
                GPU_NAME=$(lspci -nns "$addr" | sed -E 's/^[0-9a-f:.]+\s(.+)/\1/')
                print_warning "GPU at $addr ($GPU_NAME) is using driver: $DRIVER"
                
                # Check for X server usage
                if command -v lsof &> /dev/null; then
                    X_USAGE=$(lsof -n /dev/dri/* 2>/dev/null | grep -E 'X|Xorg|wayland|gdm|lightdm|sddm')
                    if [ -n "$X_USAGE" ] && [ "$VERBOSE" = true ]; then
                        print_info "X server or display manager is using GPU devices:"
                        echo "$X_USAGE" | head -5 | sed 's/^/     /'
                        if [ $(echo "$X_USAGE" | wc -l) -gt 5 ]; then
                            echo "     ... (more processes omitted) ..."
                        fi
                    fi
                fi
                
                echo "            => This GPU is currently bound to a host driver and may be in use."
                echo "            => To use it for passthrough, you need to bind it to vfio-pci instead."
                GPU_IN_USE=true
            else
                GPU_NAME=$(lspci -nns "$addr" | sed -E 's/^[0-9a-f:.]+\s(.+)/\1/')
                print_success "GPU at $addr ($GPU_NAME) is bound to vfio-pci driver and ready for passthrough."
            fi
        else
            print_info "Could not determine driver for GPU at $addr."
        fi
    done
    
    if [ "$GPU_IN_USE" = false ]; then
        print_info "No GPUs appear to be in use by the host with non-VFIO drivers."
    fi
    
    echo ""
}

# Function to check VM configuration for GPU passthrough
check_vm_passthrough_config() {
    local vmid="$1"
    local config_file="/etc/pve/qemu-server/${vmid}.conf"
    
    print_header "Checking VM ${vmid} Configuration for GPU Passthrough"
    
    # Check if VM exists
    if [ ! -f "$config_file" ]; then
        print_warning "VM ${vmid} not found. Check the VM ID and try again."
        return 1
    fi
    
    # Extract VM name
    VM_NAME=$(grep -E "^name:" "$config_file" | cut -d' ' -f2-)
    if [ -n "$VM_NAME" ]; then
        print_info "Analyzing VM: ${vmid} ($VM_NAME)"
    else
        print_info "Analyzing VM: ${vmid}"
    fi
    
    # Check for machine type (should be q35 for best compatibility)
    MACHINE_TYPE=$(grep -E "^machine:" "$config_file" | grep -o "q35" || echo "")
    if [ -n "$MACHINE_TYPE" ]; then
        print_success "VM is using q35 machine type (recommended for passthrough)"
    else
        print_warning "VM is not using q35 machine type. Q35 is recommended for GPU passthrough."
        echo "            => Edit VM hardware and set Machine to 'q35' type"
    fi
    
    # Check for PCI passthrough devices
    PCI_DEVICES=$(grep -E "^hostpci[0-9]+:" "$config_file")
    if [ -n "$PCI_DEVICES" ]; then
        print_success "VM has PCI passthrough device(s) configured:"
        echo "$PCI_DEVICES" | sed 's/^/     /'
        
        # Check for GPU devices specifically
        GPU_DEVICES_PASSED=$(echo "$PCI_DEVICES" | grep -i "10de:" || echo "")
        if [ -n "$GPU_DEVICES_PASSED" ]; then
            print_success "NVIDIA GPU devices are passed through to this VM"
        fi
        
        # Check for AMD GPU devices
        AMD_DEVICES_PASSED=$(echo "$PCI_DEVICES" | grep -i "1002:" || echo "")
        if [ -n "$AMD_DEVICES_PASSED" ]; then
            print_success "AMD GPU devices are passed through to this VM"
        fi
        
        # Check for romfile parameter
        ROM_FILE=$(echo "$PCI_DEVICES" | grep -o "romfile=[^,]*" || echo "")
        if [ -n "$ROM_FILE" ]; then
            print_success "Custom GPU ROM file is configured: $ROM_FILE"
        else
            print_info "No custom GPU ROM file configured. This may be needed for some GPUs."
            echo "            => If passthrough fails, consider extracting and specifying GPU ROM file"
        fi
    else
        print_warning "No PCI passthrough devices configured for this VM."
        echo "            => Add your GPU using the 'Add PCI Device' option in VM hardware settings"
    fi
    
    # Check for CPU settings
    CPU_TYPE=$(grep -E "^cpu:" "$config_file")
    if echo "$CPU_TYPE" | grep -q "hidden=1"; then
        print_success "CPU 'hidden' state is enabled (helps avoid GPU reset issues)"
    else
        print_info "CPU 'hidden' state not set. Consider adding 'hidden=1' to CPU options."
        echo "            => This helps avoid GPU driver detection issues in Windows VMs"
    fi
    
    # Check for OVMF/UEFI firmware
    if grep -q "bios: ovmf" "$config_file"; then
        print_success "VM is using OVMF/UEFI firmware (recommended for GPU passthrough)"
        
        # Check for EFI disk
        if grep -q "efidisk0:" "$config_file"; then
            print_success "VM has EFI disk configured"
        else
            print_warning "VM is using OVMF but no EFI disk is configured. This may cause boot issues."
        fi
    else
        print_info "VM is not using OVMF/UEFI firmware. OVMF is recommended for GPU passthrough."
    fi
    
    # Check for vfio_pci ids for this VM's GPU
    if [ -n "$PCI_DEVICES" ]; then
        # Extract PCI IDs from hostpci lines
        PCI_IDS=$(echo "$PCI_DEVICES" | grep -o "[0-9a-f]\{4\}:[0-9a-f]\{4\}" | sort -u)
        if [ -n "$PCI_IDS" ]; then
            print_info "PCI IDs passed to this VM: $PCI_IDS"
            
            # Check if these IDs are in vfio.conf
            VFIO_CONF=$(cat /etc/modprobe.d/vfio.conf 2>/dev/null || echo "")
            if [ -n "$VFIO_CONF" ]; then
                MISSING_IDS=""
                for ID in $PCI_IDS; do
                    if ! echo "$VFIO_CONF" | grep -q "$ID"; then
                        MISSING_IDS="$MISSING_IDS $ID"
                    fi
                done
                
                if [ -n "$MISSING_IDS" ]; then
                    print_warning "Some PCI IDs are not in vfio.conf: $MISSING_IDS"
                    echo "            => Add these IDs to vfio-pci 'ids' option in /etc/modprobe.d/vfio.conf"
                else
                    print_success "All PCI IDs are properly configured in vfio.conf"
                fi
            fi
        fi
    fi
    
    # Check for kernel command line options specific to GPU passthrough
    ARGS=$(grep -E "^args:" "$config_file" || echo "")
    if echo "$ARGS" | grep -q "video=efifb:off"; then
        print_success "VM has 'video=efifb:off' boot parameter (helps with some GPUs)"
    else
        print_info "Consider adding 'video=efifb:off' to VM boot parameters if using UEFI"
        echo "            => This helps with some GPUs that have issues with EFI framebuffer"
    fi
    
    echo ""
    print_info "VM Configuration Summary:"
    if grep -q "q35" <<< "$MACHINE_TYPE" && \
       [ -n "$PCI_DEVICES" ] && \
       grep -q "bios: ovmf" "$config_file"; then
        echo -e "     ${GREEN}✓${NC} Basic GPU passthrough requirements are met"
    else
        echo -e "     ${YELLOW}!${NC} Some recommended settings for GPU passthrough are missing"
    fi
    
    echo ""
}

# Function to check all VMs for GPU passthrough config
check_all_vms_passthrough_config() {
    print_header "Checking All VMs for GPU Passthrough Configuration"
    
    # Get list of all VM IDs
    VM_IDS=$(ls /etc/pve/qemu-server/ 2>/dev/null | grep -o "^[0-9]\+\.conf" | sed 's/\.conf//')
    
    if [ -z "$VM_IDS" ]; then
        print_info "No VMs found on this Proxmox host."
        return
    fi
    
    # Count VMs with GPU passthrough
    TOTAL_VMS=$(echo "$VM_IDS" | wc -l)
    GPU_PASSTHROUGH_VMS=0
    
    print_info "Found $TOTAL_VMS VMs, checking for GPU passthrough configuration..."
    echo ""
    
    for VMID in $VM_IDS; do
        CONFIG_FILE="/etc/pve/qemu-server/${VMID}.conf"
        if grep -q "hostpci" "$CONFIG_FILE"; then
            # Extract VM name
            VM_NAME=$(grep -E "^name:" "$CONFIG_FILE" | cut -d' ' -f2-)
            if [ -n "$VM_NAME" ]; then
                print_info "VM ${VMID} ($VM_NAME) has PCI passthrough configured"
            else
                print_info "VM ${VMID} has PCI passthrough configured"
            fi
            
            # Check if it's a GPU passthrough specifically
            if grep -q "hostpci" "$CONFIG_FILE" | grep -E -q "10de:|1002:"; then
                print_success "GPU passthrough detected for VM ${VMID}"
                ((GPU_PASSTHROUGH_VMS++))
                
                # Optional: offer to check this VM in detail
                if [ "$VERBOSE" = true ]; then
                    check_vm_passthrough_config "$VMID"
                fi
            fi
        fi
    done
    
    echo ""
    print_info "Found $GPU_PASSTHROUGH_VMS VMs with GPU passthrough configuration out of $TOTAL_VMS total VMs"
    
    if [ "$GPU_PASSTHROUGH_VMS" -gt 0 ]; then
        print_info "To check a specific VM in detail, run with: --vm VMID"
    fi
    
    echo ""
}

# Function to generate fix commands
generate_fix_commands() {
    print_header "Generated Fix Commands"
    
    echo -e "${BOLD}WARNING:${NC} Review these commands carefully before executing them"
    echo "These commands are based on detected issues and may need customization"
    echo ""
    
    # Detect Proxmox version for version-specific commands
    PVE_VERSION=$(detect_proxmox_version)
    PVE_MAJOR_VERSION=$(echo "$PVE_VERSION" | cut -d'.' -f1)
    
    # Check for IOMMU kernel parameters
    if [ "$IOMMU_MISSING" = true ]; then
        CPU_VENDOR=$(check_cpu_vendor)
        echo -e "${BOLD}# Enable IOMMU in kernel parameters${NC}"
        echo "# First, backup your current GRUB configuration"
        echo "cp /etc/default/grub /etc/default/grub.backup"
        echo ""
        
        if [ "$CPU_VENDOR" = "AMD" ]; then
            echo "# For AMD processors:"
            echo "sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\\1 amd_iommu=on iommu=pt\"/' /etc/default/grub"
        else
            echo "# For Intel processors:"
            echo "sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\\1 intel_iommu=on iommu=pt\"/' /etc/default/grub"
        fi
        
        echo "# Update GRUB and reboot"
        echo "update-grub"
        echo "reboot"
        echo ""
    fi
    
    # Check for missing VFIO modules
    if [ ${#MISSING_MODULES[@]} -ne 0 ]; then
        echo -e "${BOLD}# Load and configure VFIO modules${NC}"
        
        # Add modules to /etc/modules
        echo "# Add VFIO modules to /etc/modules"
        for module in "${MISSING_MODULES[@]}"; do
            echo "echo \"$module\" >> /etc/modules"
        done
        
        # Update initramfs
        echo "# Update initramfs"
        echo "update-initramfs -u -k all"
        echo ""
    fi
    
    # Check for GPU driver blacklisting
    if [ "$BLACKLIST_FOUND" = false ]; then
        echo -e "${BOLD}# Configure GPU driver blacklisting${NC}"
        echo "# Create VFIO configuration file"
        echo "cat > /etc/modprobe.d/vfio.conf << 'EOL'"
        echo "# Blacklist GPU drivers"
        echo "blacklist nouveau"
        echo "blacklist nvidia"
        echo "blacklist amdgpu"
        echo "blacklist radeon"
        echo ""
        echo "# Configure VFIO-PCI to bind to your GPU"
        echo "options vfio-pci ids=XXXX:XXXX,XXXX:XXXX"
        echo "EOL"
        echo ""
        echo "# NOTE: Replace XXXX:XXXX with your actual GPU and audio device IDs"
        echo "# You can find these IDs using: lspci -nn | grep -E 'VGA|Audio'"
        echo ""
        echo "# Update initramfs after making these changes"
        echo "update-initramfs -u -k all"
        echo ""
    fi
    
    # Generate VM-specific fix commands if a VM ID was provided
    if [ "$CHECK_VM" = true ] && [ -n "$VM_ID" ]; then
        echo -e "${BOLD}# VM-specific fixes for VM $VM_ID${NC}"
        
        # Check if it's a Windows VM
        if is_windows_vm "$VM_ID"; then
            echo "# Windows VM detected - applying Windows-specific fixes"
            
            # Get VM configuration
            CONFIG_FILE="/etc/pve/qemu-server/${VM_ID}.conf"
            if [ -f "$CONFIG_FILE" ]; then
                # Check for GPU devices
                PCI_DEVICES=$(grep -E "^hostpci[0-9]+:" "$CONFIG_FILE" || echo "")
                GPU_DEVICES=$(lspci -nn | grep -E 'VGA|3D|Display' | cut -d' ' -f1)
                
                # Generate commands based on Proxmox version
                if [ "$PVE_MAJOR_VERSION" -ge 8 ]; then
                    echo -e "\n# For Proxmox 8.x+, use these commands:"
                    echo "# 1. Set NVIDIA Code 43 prevention and Hyper-V enlightenments"
                    echo "qm set $VM_ID -args '-cpu max,kvm=off,hv_vendor_id=whatever,hv_relaxed,hv_spinlocks=0x1fff,hv_vapic,hv_time'"
                    
                    # If GPU is detected, add it to the VM
                    if [ -n "$GPU_DEVICES" ]; then
                        echo -e "\n# 2. Add GPU devices to VM"
                        FIRST_GPU=$(echo "$GPU_DEVICES" | head -1)
                        echo "qm set $VM_ID -hostpci0 '$FIRST_GPU,x-vga=on'"
                        
                        # Check for audio device
                        AUDIO_DEVICE="${FIRST_GPU%.*}.1"
                        if lspci -nn | grep -q "$AUDIO_DEVICE.*Audio"; then
                            echo "qm set $VM_ID -hostpci1 '$AUDIO_DEVICE'"
                        fi
                    fi
                    
                    echo -e "\n# 3. Disable memory ballooning for better performance"
                    echo "qm set $VM_ID -balloon 0"
                    
                    echo -e "\n# 4. Configure display settings for optimal GPU passthrough"
                    echo "# Set VGA to none for better GPU passthrough"
                    echo "qm set $VM_ID -vga none"
                    
                    echo -e "\n# 5. IMPORTANT: Avoid common GPU passthrough errors"
                    echo "# WARNING: Do NOT add GPU devices in both args and hostpci parameters"
                    echo "# WARNING: Do NOT add 'video=efifb:off' to the args string - it causes errors"
                    echo "# If you have issues with EFI framebuffer, you can add this to kernel parameters:"
                    echo "# qm set $VM_ID -kernel_cmdline 'video=efifb:off'"
                    echo "# But for most setups, this is not necessary"
                else
                    echo -e "\n# For Proxmox 7.x and earlier, use these commands:"
                    echo "# 1. Set CPU parameters for NVIDIA Code 43 prevention"
                    echo "qm set $VM_ID -cpu 'host,hidden=1,vendor_id=whatever,hv=on'"
                    
                    # If GPU is detected, add it to the VM
                    if [ -n "$GPU_DEVICES" ]; then
                        echo -e "\n# 2. Add GPU devices to VM"
                        FIRST_GPU=$(echo "$GPU_DEVICES" | head -1)
                        echo "qm set $VM_ID -hostpci0 '$FIRST_GPU,x-vga=on'"
                        
                        # Check for audio device
                        AUDIO_DEVICE="${FIRST_GPU%.*}.1"
                        if lspci -nn | grep -q "$AUDIO_DEVICE.*Audio"; then
                            echo "qm set $VM_ID -hostpci1 '$AUDIO_DEVICE'"
                        fi
                    fi
                    
                    echo -e "\n# 3. Disable memory ballooning for better performance"
                    echo "qm set $VM_ID -balloon 0"
                fi
            fi
        else
            echo "# Non-Windows VM - applying generic fixes"
            # Add generic VM fixes here
        fi
    fi
    
    echo -e "${BOLD}# After making these changes, reboot your system${NC}"
    echo "reboot"
    echo ""
    
    echo -e "${BOLD}# After reboot, verify IOMMU is enabled${NC}"
    echo "dmesg | grep -iE 'IOMMU|DMAR|AMD-Vi'"
    echo ""
    
    echo -e "${BOLD}# Run this script again to verify your changes${NC}"
    echo "bash proxmox-gpu-passthrough-check.sh"
    echo ""
}

# Function to print summary
print_summary() {
    print_header "Summary of GPU Passthrough Readiness Checks"
    
    echo -e "${BOLD}Successful checks:${NC}"
    if [ ${#SUCCESS_CHECKS[@]} -eq 0 ]; then
        echo "   None"
    else
        for check in "${SUCCESS_CHECKS[@]}"; do
            echo -e "   ${GREEN}✓${NC} $check"
        done
    fi
    
    echo -e "\n${BOLD}Warnings:${NC}"
    if [ ${#WARNING_CHECKS[@]} -eq 0 ]; then
        echo "   None"
    else
        for check in "${WARNING_CHECKS[@]}"; do
            echo -e "   ${YELLOW}!${NC} $check"
        done
    fi
    
    # Calculate script execution time
    SCRIPT_END_TIME=$(date +%s.%N)
    EXECUTION_TIME=$(echo "$SCRIPT_END_TIME - $SCRIPT_START_TIME" | bc)
    printf "\nScript execution time: %.2f seconds\n" $EXECUTION_TIME
    
    echo -e "\n${BOLD}Next Steps:${NC}"
    if [ ${#WARNING_CHECKS[@]} -eq 0 ]; then
        echo -e "${GREEN}Your system appears to be ready for GPU passthrough!${NC}"
        
        # CPU vendor specific advice
        CPU_VENDOR=$(check_cpu_vendor)
        if [ "$CPU_VENDOR" = "AMD" ]; then
            echo "1. Identify the GPU you want to pass through (check IOMMU Group section)"
            echo "2. Configure your VM for GPU passthrough:"
            echo "   - Use q35 machine type"
            echo "   - Use OVMF/UEFI firmware"
            echo "   - Add PCI device with your GPU ID"
            echo "   - Set CPU type with 'hidden=1' option"
            echo "   - Consider adding 'video=efifb:off' to VM boot parameters"
            echo "3. For AMD GPUs, be aware of potential reset issues"
            echo "   - See: https://github.com/gnif/vendor-reset for solutions"
        elif [ "$CPU_VENDOR" = "Intel" ]; then
            echo "1. Identify the GPU you want to pass through (check IOMMU Group section)"
            echo "2. Configure your VM for GPU passthrough:"
            echo "   - Use q35 machine type"
            echo "   - Use OVMF/UEFI firmware"
            echo "   - Add PCI device with your GPU ID"
            echo "   - Set CPU type with 'hidden=1' option"
        else
            echo "1. Identify the GPU you want to pass through and its IOMMU group"
            echo "2. Configure your VM for GPU passthrough (add PCI device, use q35 machine type, etc.)"
        fi
        echo "3. Test your VM with the passed-through GPU"
        echo "4. Use '--vm VMID' option to check if your VM is properly configured"
    else
        echo -e "${YELLOW}Your system needs some configuration for GPU passthrough.${NC}"
        
        # Check for common issues and provide specific instructions
        if echo "${WARNING_CHECKS[*]}" | grep -q "intel_iommu=on.*NOT found"; then
            CPU_VENDOR=$(check_cpu_vendor)
            echo -e "\n${BOLD}IOMMU Configuration:${NC}"
            echo "1. Edit GRUB: nano /etc/default/grub"
            if [ "$CPU_VENDOR" = "AMD" ]; then
                echo "2. Add 'amd_iommu=on iommu=pt' to GRUB_CMDLINE_LINUX_DEFAULT"
            else
                echo "2. Add 'intel_iommu=on iommu=pt' to GRUB_CMDLINE_LINUX_DEFAULT"
            fi
            echo "3. Run: update-grub"
            echo "4. Reboot: reboot"
        fi
        
        if echo "${WARNING_CHECKS[*]}" | grep -q "No GPU driver blacklist"; then
            echo -e "\n${BOLD}GPU Driver Blacklisting:${NC}"
            echo "1. Create a file: nano /etc/modprobe.d/vfio.conf"
            echo "2. Add appropriate blacklist entries for your GPU"
            echo "3. Add 'options vfio-pci ids=XXXX:XXXX,XXXX:XXXX' with your GPU IDs"
            echo "4. Run: update-initramfs -u -k all"
            echo "5. Reboot: reboot"
        fi
        
        echo -e "\n${BOLD}After addressing these issues:${NC}"
        echo "1. Run this script again to verify your changes"
        echo "2. Configure your VM for GPU passthrough"
        echo "3. Use '--vm VMID' option to check if your VM is properly configured"
        
        if [ "$GENERATE_FIX" = false ]; then
            echo -e "\nTip: Run with '--generate-fix' to get commands that may help fix these issues"
        fi
    fi
    
    echo -e "\n${BOLD}For more information:${NC}"
    echo "- Proxmox Wiki: https://pve.proxmox.com/wiki/PCI_Passthrough"
    echo "- Proxmox IOMMU Configuration: https://pve.proxmox.com/wiki/PCI_Passthrough#Verifying_IOMMU_parameters"
    echo "- Proxmox Forum: https://forum.proxmox.com/"
    echo "- GPU Passthrough Guide: https://www.reddit.com/r/homelab/wiki/hardware/pci-passthrough/"
}

# Function to display interactive menu
display_interactive_menu() {
    clear
    echo -e "${BOLD}=== Proxmox GPU Passthrough Readiness Check Script v2.2 ===${NC}"
    echo "This script checks for common GPU passthrough prerequisites on a Proxmox VE host."
    echo "It does NOT make any changes to your system."
    echo ""
    
    PS3="Please select an option (1-12): "
    options=(
        "Run all host checks (recommended)"
        "Check IOMMU in kernel command line"
        "Check IOMMU in dmesg"
        "Check VFIO modules"
        "List IOMMU groups"
        "List GPU devices"
        "Check CPU virtualization support"
        "Check Secure Boot status"
        "Check GPU driver blacklisting"
        "Check if GPU is in use by the host"
        "Check specific VM for GPU passthrough"
        "Check all VMs for GPU passthrough"
        "Generate fix commands"
        "Exit"
    )
    
    select opt in "${options[@]}"
    do
        case $opt in
            "Run all host checks (recommended)")
                CHECK_HOST=true
                break
                ;;
            "Check IOMMU in kernel command line")
                CHECK_HOST=false
                CHECK_IOMMU_KERNEL=true
                break
                ;;
            "Check IOMMU in dmesg")
                CHECK_HOST=false
                CHECK_IOMMU_DMESG=true
                break
                ;;
            "Check VFIO modules")
                CHECK_HOST=false
                CHECK_VFIO=true
                break
                ;;
            "List IOMMU groups")
                CHECK_HOST=false
                CHECK_IOMMU_GROUPS=true
                break
                ;;
            "List GPU devices")
                CHECK_HOST=false
                CHECK_GPU=true
                break
                ;;
            "Check CPU virtualization support")
                CHECK_HOST=false
                CHECK_CPU_VIRT=true
                break
                ;;
            "Check Secure Boot status")
                CHECK_HOST=false
                CHECK_SECURE_BOOT=true
                break
                ;;
            "Check GPU driver blacklisting")
                CHECK_HOST=false
                CHECK_BLACKLIST=true
                break
                ;;
            "Check if GPU is in use by the host")
                CHECK_HOST=false
                CHECK_GPU_USAGE=true
                break
                ;;
            "Check specific VM for GPU passthrough")
                CHECK_HOST=false
                CHECK_VM=true
                echo -e "\nEnter VM ID to check:"
                read -r VM_ID
                if [[ ! "$VM_ID" =~ ^[0-9]+$ ]]; then
                    echo "Invalid VM ID. Please enter a numeric value."
                    exit 1
                fi
                break
                ;;
            "Check all VMs for GPU passthrough")
                CHECK_HOST=false
                CHECK_ALL_VMS=true
                break
                ;;
            "Generate fix commands")
                GENERATE_FIX=true
                echo -e "\nDo you want to run host checks as well? (y/n)"
                read -r run_host
                if [[ "$run_host" =~ ^[Yy]$ ]]; then
                    CHECK_HOST=true
                else
                    CHECK_HOST=false
                fi
                break
                ;;
            "Exit")
                echo "Exiting script."
                exit 0
                ;;
            *) 
                echo "Invalid option $REPLY. Please try again."
                ;;
        esac
    done
    
    # Ask for verbose mode
    echo -e "\nEnable verbose output? (y/n)"
    read -r verbose
    if [[ "$verbose" =~ ^[Yy]$ ]]; then
        VERBOSE=true
    fi
    
    clear
}

# Main function
main() {
    # Print script header
    echo -e "${BOLD}=== Proxmox GPU Passthrough Readiness Check Script v2.2 ===${NC}"
    echo "This script checks for common GPU passthrough prerequisites on a Proxmox VE host."
    echo "It does NOT make any changes to your system."
    echo ""
    
    # Check if running as root
    check_root
    
    # Check for required dependencies
    check_dependencies
    
    # Run host checks if not skipped
    if [ "$SKIP_HOST_CHECKS" = false ]; then
        if [ "$CHECK_HOST" = true ] || [ "$CHECK_IOMMU_KERNEL" = true ]; then
            check_iommu_kernel
        fi
        
        if [ "$CHECK_HOST" = true ] || [ "$CHECK_IOMMU_DMESG" = true ]; then
            check_iommu_dmesg
        fi
        
        if [ "$CHECK_HOST" = true ] || [ "$CHECK_VFIO" = true ]; then
            check_vfio_modules
        fi
        
        if [ "$CHECK_HOST" = true ] || [ "$CHECK_IOMMU_GROUPS" = true ]; then
            list_iommu_groups
        fi
        
        if [ "$CHECK_HOST" = true ] || [ "$CHECK_GPU" = true ]; then
            list_gpu_devices
        fi
        
        if [ "$CHECK_HOST" = true ] || [ "$CHECK_CPU_VIRT" = true ]; then
            check_cpu_virtualization
        fi
        
        if [ "$CHECK_HOST" = true ] || [ "$CHECK_SECURE_BOOT" = true ]; then
            check_secure_boot
        fi
        
        if [ "$CHECK_HOST" = true ] || [ "$CHECK_BLACKLIST" = true ]; then
            check_gpu_driver_blacklist
        fi
        
        if [ "$CHECK_HOST" = true ] || [ "$CHECK_GPU_USAGE" = true ]; then
            check_gpu_usage
        fi
    fi
    
    # Run VM checks
    if [ "$CHECK_VM" = true ] && [ -n "$VM_ID" ]; then
        # Basic VM configuration check
        check_vm_passthrough_config "$VM_ID"
        
        # Check if it's a Windows VM
        if is_windows_vm "$VM_ID"; then
            check_windows_gpu_passthrough "$VM_ID"
        fi
        
        # Runtime checks if VM is running and runtime checks are not skipped
        if [ "$SKIP_RUNTIME_CHECKS" = false ]; then
            if check_vm_running_state "$VM_ID"; then
                check_vm_runtime "$VM_ID"
            fi
        fi
    fi
    
    if [ "$CHECK_ALL_VMS" = true ]; then
        check_all_vms_passthrough_config
    fi
    
    if [ "$GENERATE_FIX" = true ]; then
        generate_fix_commands
    fi
    
    # Print summary
    if [ "$SHOW_SUMMARY" = true ]; then
        print_summary
    fi
    
    echo -e "\n${BOLD}=== Check Complete ===${NC}"
    echo "For one-line execution on any Proxmox host, use:"
    echo "curl -s https://raw.githubusercontent.com/talltechy/proxmox-gpu-passthrough-check/main/proxmox-gpu-passthrough-check.sh | bash"
    echo "or"
    echo "wget -qO- https://raw.githubusercontent.com/talltechy/proxmox-gpu-passthrough-check/main/proxmox-gpu-passthrough-check.sh | bash"
}

# Function to detect if a VM is running
check_vm_running_state() {
    local vmid="$1"
    
    # Check if qm command exists
    if ! command -v qm &> /dev/null; then
        print_warning "qm command not found. Cannot check VM running state."
        return 1
    fi
    
    # Check VM status
    local vm_status=$(qm status "$vmid" 2>/dev/null | awk '{print $2}')
    
    if [ "$vm_status" = "running" ]; then
        return 0  # VM is running
    else
        return 1  # VM is not running
    fi
}

# Function to detect Windows VM
is_windows_vm() {
    local vmid="$1"
    local config_file="/etc/pve/qemu-server/${vmid}.conf"
    
    # Check if VM exists
    if [ ! -f "$config_file" ]; then
        return 1
    fi
    
    # Check for Windows indicators in config
    if grep -q -E "ostype: (win|windows|w2k|wxp|w2k3|w2k8|wvista|win7|win8|win10|win11)" "$config_file"; then
        return 0  # It's a Windows VM
    fi
    
    # Check for Windows-specific boot parameters
    if grep -q -E "args:.*Windows" "$config_file"; then
        return 0  # It's likely a Windows VM
    fi
    
    # Check for Windows-specific disk images
    if grep -q -E "virtio.*windows" "$config_file"; then
        return 0  # It's likely a Windows VM
    fi
    
    return 1  # Not a Windows VM or can't determine
}

# Function to detect Proxmox version
detect_proxmox_version() {
    if command -v pveversion &> /dev/null; then
        local pve_version=$(pveversion -v | grep "pve-manager:" | cut -d' ' -f2)
        echo "$pve_version"
    else
        echo "unknown"
    fi
}

# Function to check Windows-specific GPU passthrough settings
check_windows_gpu_passthrough() {
    local vmid="$1"
    local config_file="/etc/pve/qemu-server/${vmid}.conf"
    
    print_header "Windows-Specific GPU Passthrough Checks for VM ${vmid}"
    
    # Check if VM exists
    if [ ! -f "$config_file" ]; then
        print_warning "VM ${vmid} not found. Check the VM ID and try again."
        return 1
    fi
    
    # Extract VM name
    VM_NAME=$(grep -E "^name:" "$config_file" | cut -d' ' -f2-)
    if [ -n "$VM_NAME" ]; then
        print_info "Analyzing Windows VM: ${vmid} ($VM_NAME)"
    else
        print_info "Analyzing Windows VM: ${vmid}"
    fi
    
    # Detect Proxmox version for version-specific commands
    PVE_VERSION=$(detect_proxmox_version)
    PVE_MAJOR_VERSION=$(echo "$PVE_VERSION" | cut -d'.' -f1)
    
    # Check for CPU hidden state (important for NVIDIA Code 43 error)
    CPU_TYPE=$(grep -E "^cpu:" "$config_file")
    ARGS_LINE=$(grep -E "^args:" "$config_file" || echo "")
    
    # Check for Code 43 prevention settings in args
    if echo "$ARGS_LINE" | grep -q "kvm=off" && echo "$ARGS_LINE" | grep -q "hv_vendor_id"; then
        print_success "NVIDIA Code 43 prevention settings found in args parameter"
    elif echo "$CPU_TYPE" | grep -q "hidden=1"; then
        print_success "CPU 'hidden=1' is set (prevents NVIDIA Code 43 error)"
    else
        print_warning "NVIDIA Code 43 prevention settings not found. This is required for NVIDIA GPUs."
        echo "            => For Proxmox 8.x+, use args parameter with kvm=off and hv_vendor_id"
        if [ "$GENERATE_FIX" = true ]; then
            if [ "$PVE_MAJOR_VERSION" -ge 8 ]; then
                echo "            => Fix command: qm set $vmid -args '-cpu max,kvm=off,hv_vendor_id=whatever,hv_relaxed,hv_spinlocks=0x1fff,hv_vapic,hv_time'"
            else
                echo "            => Fix command: qm set $vmid -cpu 'host,hidden=1'"
            fi
        fi
    fi
    
    # Check for Hyper-V enlightenments
    if echo "$ARGS_LINE" | grep -q "hv_relaxed" || echo "$ARGS_LINE" | grep -q "hv_vapic" || \
       grep -q -E "args:.*hv_vendor_id|cpu:.*hv=on" "$config_file"; then
        print_success "Hyper-V enlightenments are enabled (improves Windows VM performance)"
    else
        print_warning "Hyper-V enlightenments not detected. Adding them is recommended for better Windows performance."
        if [ "$GENERATE_FIX" = true ]; then
            if [ "$PVE_MAJOR_VERSION" -ge 8 ]; then
                echo "            => Fix command: qm set $vmid -args '-cpu max,kvm=off,hv_vendor_id=whatever,hv_relaxed,hv_spinlocks=0x1fff,hv_vapic,hv_time'"
            else
                if echo "$CPU_TYPE" | grep -q "hidden=1" && echo "$CPU_TYPE" | grep -q "vendor_id="; then
                    CURRENT_CPU=$(echo "$CPU_TYPE" | sed -E 's/^cpu: //')
                    echo "            => Fix command: qm set $vmid -cpu '$CURRENT_CPU,hv=on'"
                else
                    echo "            => Fix command: qm set $vmid -cpu 'host,hidden=1,vendor_id=whatever,hv=on'"
                fi
            fi
        fi
    fi
    
    # Check for CPU flags that improve GPU passthrough performance
    if echo "$CPU_TYPE" | grep -q "flags="; then
        print_success "CPU flags are explicitly set (can improve GPU passthrough performance)"
        
        # Check for specific important flags
        CPU_FLAGS=$(echo "$CPU_TYPE" | grep -o "flags=[^,]*" || echo "")
        if [ -n "$CPU_FLAGS" ]; then
            if echo "$CPU_FLAGS" | grep -q "+pcid"; then
                print_info "PCID flag is enabled (improves context switching performance)"
            fi
            if echo "$CPU_FLAGS" | grep -q "+ssse3"; then
                print_info "SSSE3 flag is enabled (important for some GPU workloads)"
            fi
            if echo "$CPU_FLAGS" | grep -q "+topoext"; then
                print_info "TOPOEXT flag is enabled (improves topology awareness for AMD CPUs)"
            fi
        fi
    else
        print_info "No explicit CPU flags set. Consider adding flags for optimal GPU passthrough performance."
        echo "            => Recommended flags depend on your CPU and workload"
        echo "            => For gaming: +pcid,+ssse3,+sse4_1,+sse4_2,+popcnt,+avx,+aes"
        if [ "$GENERATE_FIX" = true ]; then
            if echo "$CPU_TYPE" | grep -q "host"; then
                CURRENT_CPU=$(echo "$CPU_TYPE" | sed -E 's/^cpu: //')
                echo "            => Fix command: qm set $vmid -cpu '$CURRENT_CPU,flags=+pcid;+ssse3;+sse4_1;+sse4_2;+aes'"
            else
                echo "            => Fix command: qm set $vmid -cpu 'host,flags=+pcid;+ssse3;+sse4_1;+sse4_2;+aes'"
            fi
        fi
    fi
    
    # Check for x-vga=on parameter for NVIDIA GPUs
    PCI_DEVICES=$(grep -E "^hostpci[0-9]+:" "$config_file")
    if echo "$PCI_DEVICES" | grep -q "10de:"; then
        if echo "$PCI_DEVICES" | grep -q "x-vga=on"; then
            print_success "x-vga=on parameter is set for NVIDIA GPU (better compatibility)"
        else
            print_warning "x-vga=on parameter is missing for NVIDIA GPU. Adding it is recommended."
            echo "            => This improves compatibility with NVIDIA GPUs in Windows"
            if [ "$GENERATE_FIX" = true ]; then
                # Extract the hostpci line with NVIDIA GPU
                NVIDIA_PCI_LINE=$(echo "$PCI_DEVICES" | grep "10de:" | head -1)
                if [ -n "$NVIDIA_PCI_LINE" ]; then
                    PCI_ID=$(echo "$NVIDIA_PCI_LINE" | cut -d: -f1)
                    PCI_VALUE=$(echo "$NVIDIA_PCI_LINE" | cut -d: -f2-)
                    echo "            => Fix command: qm set $vmid -${PCI_ID} ${PCI_VALUE},x-vga=on"
                fi
            fi
        fi
    fi
    
    # Check for MSI interrupts
    if echo "$PCI_DEVICES" | grep -q "pcie=1"; then
        print_success "PCIe option is enabled for PCI passthrough (better performance)"
    else
        print_warning "PCIe option (pcie=1) is missing. Adding it is recommended for better performance."
        echo "            => This improves interrupt handling for passthrough devices"
        if [ "$GENERATE_FIX" = true ]; then
            # Extract the first hostpci line
            PCI_LINE=$(echo "$PCI_DEVICES" | head -1)
            if [ -n "$PCI_LINE" ]; then
                PCI_ID=$(echo "$PCI_LINE" | cut -d: -f1)
                PCI_VALUE=$(echo "$PCI_LINE" | cut -d: -f2-)
                echo "            => Fix command: qm set $vmid -${PCI_ID} ${PCI_VALUE},pcie=1"
            fi
        fi
    fi
    
    # Check for multifunction option
    if echo "$PCI_DEVICES" | grep -q "multifunction=on"; then
        print_success "Multifunction option is enabled (required for GPU + audio passthrough)"
    elif echo "$PCI_DEVICES" | grep -E -q "10de:.*10de:"; then
        print_warning "Multiple NVIDIA devices detected without multifunction=on option."
        echo "            => This is required for proper GPU + audio passthrough"
        if [ "$GENERATE_FIX" = true ]; then
            # Extract the hostpci line with NVIDIA GPU
            NVIDIA_PCI_LINE=$(echo "$PCI_DEVICES" | grep "10de:" | head -1)
            if [ -n "$NVIDIA_PCI_LINE" ]; then
                PCI_ID=$(echo "$NVIDIA_PCI_LINE" | cut -d: -f1)
                PCI_VALUE=$(echo "$NVIDIA_PCI_LINE" | cut -d: -f2-)
                echo "            => Fix command: qm set $vmid -${PCI_ID} ${PCI_VALUE},multifunction=on"
            fi
        fi
    fi
    
    # Check for ROM file with NVIDIA GPUs
    if echo "$PCI_DEVICES" | grep -q "10de:" && ! echo "$PCI_DEVICES" | grep -q "romfile="; then
        print_warning "NVIDIA GPU detected without ROM file. Using a dumped ROM file is recommended."
        echo "            => This can help with GPU initialization issues and Code 43 errors"
        echo "            => You need to dump your GPU ROM first and place it in /usr/share/kvm/"
    fi
    
    # Check for CPU pinning (performance optimization)
    if grep -q -E "^args:.*isolcpus|^cpu:.*cpulimit|^numa:" "$config_file"; then
        print_success "CPU pinning or limits detected (performance optimization)"
    else
        print_warning "CPU pinning is not configured. This is recommended for gaming performance."
        echo "            => Use 'cpulimit' in CPU options or NUMA settings"
        if [ "$GENERATE_FIX" = true ]; then
            echo "            => Example fix command: qm set $vmid -args '-cpu host,pinned'"
            echo "            => Or use NUMA settings for more precise control"
        fi
    fi
    
    # Check for memory ballooning (can cause performance issues)
    if grep -q "balloon: 0" "$config_file"; then
        print_success "Memory ballooning is disabled (better for gaming performance)"
    else
        print_warning "Memory ballooning is enabled. Disabling it is recommended for gaming performance."
        echo "            => Set 'balloon: 0' in VM configuration"
        if [ "$GENERATE_FIX" = true ]; then
            echo "            => Fix command: qm set $vmid -balloon 0"
        fi
    fi
    
    # Check for machine type
    MACHINE_TYPE=$(grep -E "^machine:" "$config_file" || echo "")
    if echo "$MACHINE_TYPE" | grep -q "q35"; then
        if echo "$MACHINE_TYPE" | grep -q "pc-q35-[0-9]"; then
            print_success "Using modern q35 machine type: $(echo "$MACHINE_TYPE" | cut -d: -f2-)"
        else
            print_success "Using q35 machine type (recommended for passthrough)"
        fi
    else
        print_warning "Not using q35 machine type. This is strongly recommended for GPU passthrough."
        echo "            => Edit VM hardware and set Machine to 'q35' type"
        if [ "$GENERATE_FIX" = true ]; then
            echo "            => Fix command: qm set $vmid -machine q35"
        fi
    fi
    
    # Check for vIOMMU setting
    if grep -q "machine:.*,iommu=on" "$config_file" || grep -q "args:.*-device intel-iommu" "$config_file"; then
        print_success "IOMMU is enabled in the VM (required for some passthrough scenarios)"
    else
        print_info "IOMMU is not explicitly enabled in the VM. This may be needed for some devices."
        echo "            => Consider adding 'iommu=on' to machine options if you have issues"
        if [ "$GENERATE_FIX" = true ]; then
            if [ -n "$MACHINE_TYPE" ]; then
                CURRENT_MACHINE=$(echo "$MACHINE_TYPE" | sed -E 's/^machine: //')
                echo "            => Fix command: qm set $vmid -machine ${CURRENT_MACHINE},iommu=on"
            fi
        fi
    fi
    
    # Check display settings
    DISPLAY_TYPE=$(grep -E "^vga:" "$config_file" || echo "")
    if [ -n "$DISPLAY_TYPE" ]; then
        if echo "$DISPLAY_TYPE" | grep -q "none"; then
            print_success "Display is set to 'none' (optimal for GPU passthrough)"
        elif echo "$DISPLAY_TYPE" | grep -q "std"; then
            print_success "Display is set to 'std' (compatible with GPU passthrough)"
        else
            print_warning "Display is not set to 'none' or 'std'. This may interfere with GPU passthrough."
            echo "            => For optimal GPU passthrough, set Display to 'none' or 'std'"
            if [ "$GENERATE_FIX" = true ]; then
                echo "            => Fix command: qm set $vmid -vga none"
                echo "            => Alternative: qm set $vmid -vga std"
            fi
        fi
    else
        print_warning "No display configuration found. For GPU passthrough, set Display to 'none' or 'std'."
        if [ "$GENERATE_FIX" = true ]; then
            echo "            => Fix command: qm set $vmid -vga none"
        fi
    fi
    
    # Check for SPICE/VNC settings that might interfere with GPU passthrough
    if grep -q "spice" "$config_file"; then
        print_info "SPICE display is enabled. This may be redundant with GPU passthrough."
        echo "            => Consider disabling SPICE if you're using the passthrough GPU for display"
        if [ "$GENERATE_FIX" = true ]; then
            echo "            => Fix command: qm set $vmid -vga none -spice 0"
        fi
    fi
    
    echo ""
    print_info "Windows-Specific Configuration Summary:"
    ISSUES_COUNT=0
    
    if ! echo "$CPU_TYPE" | grep -q "hidden=1"; then
        ((ISSUES_COUNT++))
    fi
    
    if ! echo "$CPU_TYPE" | grep -q "vendor_id="; then
        ((ISSUES_COUNT++))
    fi
    
    if ! grep -q -E "args:.*hv_vendor_id|cpu:.*hv=on" "$config_file"; then
        ((ISSUES_COUNT++))
    fi
    
    if echo "$PCI_DEVICES" | grep -q "10de:" && ! echo "$PCI_DEVICES" | grep -q "x-vga=on"; then
        ((ISSUES_COUNT++))
    fi
    
    if ! echo "$PCI_DEVICES" | grep -q "pcie=1"; then
        ((ISSUES_COUNT++))
    fi
    
    if echo "$PCI_DEVICES" | grep -E -q "10de:.*10de:" && ! echo "$PCI_DEVICES" | grep -q "multifunction=on"; then
        ((ISSUES_COUNT++))
    fi
    
    if ! grep -q "balloon: 0" "$config_file"; then
        ((ISSUES_COUNT++))
    fi
    
    if [ $ISSUES_COUNT -eq 0 ]; then
        echo -e "     ${GREEN}✓${NC} All Windows GPU passthrough optimizations are properly configured"
    elif [ $ISSUES_COUNT -le 2 ]; then
        echo -e "     ${YELLOW}!${NC} Some recommended Windows-specific settings are missing ($ISSUES_COUNT issues)"
    else
        echo -e "     ${RED}!${NC} Multiple recommended Windows-specific settings are missing ($ISSUES_COUNT issues)"
        echo "     => These settings are important for optimal GPU passthrough performance in Windows"
        if [ "$GENERATE_FIX" = false ]; then
            echo "     => Run with --generate-fix to see commands to fix these issues"
        fi
    fi
    
    echo ""
}

# Function to check runtime VM state for GPU passthrough
check_vm_runtime() {
    local vmid="$1"
    
    print_header "Runtime Checks for VM ${vmid}"
    
    # Check if VM is running
    if ! check_vm_running_state "$vmid"; then
        print_info "VM ${vmid} is not running. Skipping runtime checks."
        echo "            => Start the VM to perform runtime checks"
        return 1
    fi
    
    print_success "VM ${vmid} is running. Performing runtime checks..."
    
    # Check if it's a Windows VM
    if is_windows_vm "$vmid"; then
        print_info "Detected Windows VM. Performing Windows-specific runtime checks."
        
        # Here we would ideally connect to the VM via SSH or agent and check:
        # - Device Manager status
        # - GPU driver installation
        # - Code 43 errors
        # - Performance metrics
        
        # For now, we'll just provide guidance
        print_info "To verify GPU passthrough is working in Windows:"
        echo "            1. Check Device Manager for the GPU (should not show Code 43 error)"
        echo "            2. Install appropriate GPU drivers"
        echo "            3. Run GPU-Z or similar tool to verify GPU is recognized"
        echo "            4. Test with a 3D application or benchmark"
    else
        print_info "Non-Windows VM detected. Performing generic runtime checks."
        
        # Generic runtime checks guidance
        print_info "To verify GPU passthrough is working:"
        echo "            1. Connect to the VM console or SSH"
        echo "            2. Check for GPU with 'lspci -nnk'"
        echo "            3. Install appropriate GPU drivers"
        echo "            4. Test with a GPU-accelerated application"
    fi
    
    echo ""
}

# Parse command line arguments
# Check if no arguments were provided
if [[ $# -eq 0 ]]; then
    # No arguments, display interactive menu
    display_interactive_menu
fi

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_usage
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -k|--kernel)
            CHECK_HOST=false
            CHECK_IOMMU_KERNEL=true
            shift
            ;;
        -d|--dmesg)
            CHECK_HOST=false
            CHECK_IOMMU_DMESG=true
            shift
            ;;
        -m|--modules)
            CHECK_HOST=false
            CHECK_VFIO=true
            shift
            ;;
        -g|--groups)
            CHECK_HOST=false
            CHECK_IOMMU_GROUPS=true
            shift
            ;;
        -p|--gpu)
            CHECK_HOST=false
            CHECK_GPU=true
            shift
            ;;
        -c|--cpu)
            CHECK_HOST=false
            CHECK_CPU_VIRT=true
            shift
            ;;
        -s|--secure-boot)
            CHECK_HOST=false
            CHECK_SECURE_BOOT=true
            shift
            ;;
        -b|--blacklist)
            CHECK_HOST=false
            CHECK_BLACKLIST=true
            shift
            ;;
        -u|--gpu-usage)
            CHECK_HOST=false
            CHECK_GPU_USAGE=true
            shift
            ;;
        --vm)
            CHECK_VM=true
            if [[ -n "$2" && "$2" =~ ^[0-9]+$ ]]; then
                VM_ID="$2"
                shift 2
            else
                print_error "Error: --vm requires a valid VM ID number"
            fi
            ;;
        --all-vms)
            CHECK_ALL_VMS=true
            shift
            ;;
        --host-only)
            CHECK_VM=false
            CHECK_ALL_VMS=false
            shift
            ;;
        --skip-host)
            CHECK_HOST=false
            SKIP_HOST_CHECKS=true
            shift
            ;;
        --skip-runtime)
            SKIP_RUNTIME_CHECKS=true
            shift
            ;;
        --generate-fix)
            GENERATE_FIX=true
            shift
            ;;
        --no-summary)
            SHOW_SUMMARY=false
            shift
            ;;
        --all)
            CHECK_HOST=true
            CHECK_IOMMU_KERNEL=true
            CHECK_IOMMU_DMESG=true
            CHECK_VFIO=true
            CHECK_IOMMU_GROUPS=true
            CHECK_GPU=true
            CHECK_CPU_VIRT=true
            CHECK_SECURE_BOOT=true
            CHECK_BLACKLIST=true
            CHECK_GPU_USAGE=true
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            ;;
    esac
done

# Run the main function
main
