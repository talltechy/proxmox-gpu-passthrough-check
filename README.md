# Proxmox GPU Passthrough Check Script

## Overview

The Proxmox GPU Passthrough Check Script is a diagnostic tool that helps Proxmox administrators verify if their system meets the prerequisites for GPU passthrough to virtual machines. This script performs a series of non-destructive checks to identify potential issues and provides guidance on how to address them.

**Version 2.2 Updates:**
- Simultaneous host and VM checks (can now run both with a single command)
- Windows-specific GPU passthrough checks
- Automatic detection of running VMs with runtime validation
- Enhanced CPU vendor detection for targeted advice
- Improved command-line options for more flexibility
- Proxmox version detection with version-specific commands
- Interactive menu for easier usage without command-line options
- Improved fix generation with version-specific commands for Proxmox 8.x+
- EFI framebuffer settings for better GPU compatibility

## Features

- **Color-coded output** for better visual distinction between SUCCESS, WARNING, and INFO messages
- **Comprehensive host system checks** including:
  - IOMMU enablement in kernel command line
  - IOMMU initialization in dmesg
  - VFIO module loading status
  - IOMMU grouping for devices
  - GPU device identification and driver usage
  - CPU virtualization support
  - Secure Boot status
  - GPU driver blacklisting
  - GPU usage by the host
- **VM configuration checks** for GPU passthrough readiness:
  - Machine type (q35 recommended)
  - PCI device configuration
  - GPU device detection
  - Custom ROM file configuration
  - CPU settings (hidden state)
  - OVMF/UEFI firmware configuration
  - Boot parameters
- **Fix generation** to help resolve detected issues
- **CPU vendor detection** for targeted advice (AMD vs Intel)
- **Summary section** providing an overview of all check results
- **Command-line options** for selective checks and verbose output
- **Performance optimizations** for faster execution
- **One-line execution** for easy deployment and use

## Requirements

- Proxmox VE host
- Root access (recommended, but not required)
- Basic Linux utilities (grep, sed, lsmod, lspci, dmesg)

## Usage

### Basic Usage

```bash
bash proxmox-gpu-passthrough-check.sh
```

This will display an interactive menu where you can select which checks to run. The menu provides easy access to all the script's features without needing to remember command-line options.

### Interactive Menu

When run without any arguments, the script displays a user-friendly menu with the following options:

1. Run all host checks (recommended)
2. Check IOMMU in kernel command line
3. Check IOMMU in dmesg
4. Check VFIO modules
5. List IOMMU groups
6. List GPU devices
7. Check CPU virtualization support
8. Check Secure Boot status
9. Check GPU driver blacklisting
10. Check if GPU is in use by the host
11. Check specific VM for GPU passthrough
12. Check all VMs for GPU passthrough
13. Generate fix commands
14. Exit

Simply select the number corresponding to the desired option. For some options, like checking a specific VM, the script will prompt for additional information.

### One-Line Execution

You can run the script directly from the repository without downloading it first:

```bash
curl -s https://raw.githubusercontent.com/talltechy/proxmox-gpu-passthrough-check/main/proxmox-gpu-passthrough-check.sh | bash
```

or

```bash
wget -qO- https://raw.githubusercontent.com/talltechy/proxmox-gpu-passthrough-check/main/proxmox-gpu-passthrough-check.sh | bash
```

### Command-Line Options

The script supports several command-line options:

- `-h, --help`: Show help message
- `-v, --verbose`: Enable verbose output
- `-k, --kernel`: Check IOMMU in kernel command line only
- `-d, --dmesg`: Check IOMMU in dmesg only
- `-m, --modules`: Check VFIO modules only
- `-g, --groups`: List IOMMU groups only
- `-p, --gpu`: List GPU devices only
- `-c, --cpu`: Check CPU virtualization support only
- `-s, --secure-boot`: Check Secure Boot status only
- `-b, --blacklist`: Check GPU driver blacklisting only
- `-u, --gpu-usage`: Check if GPU is in use by the host only
- `--vm VMID`: Check if the specified VM is properly configured for GPU passthrough
- `--all-vms`: Check all VMs for GPU passthrough configuration
- `--host-only`: Only run host checks, skip VM checks
- `--skip-host`: Skip host checks, only run VM checks
- `--skip-runtime`: Skip runtime checks for running VMs
- `--generate-fix`: Generate commands to fix detected issues (does not execute them)
- `--no-summary`: Don't show summary at the end
- `--all`: Run all host checks (default)

### Examples

Run all checks with verbose output:
```bash
curl -s https://raw.githubusercontent.com/talltechy/proxmox-gpu-passthrough-check/main/proxmox-gpu-passthrough-check.sh | bash -s -- -v
```

Check IOMMU in kernel and dmesg only:
```bash
curl -s https://raw.githubusercontent.com/talltechy/proxmox-gpu-passthrough-check/main/proxmox-gpu-passthrough-check.sh | bash -s -- -k -d
```

List IOMMU groups and GPU devices only:
```bash
curl -s https://raw.githubusercontent.com/talltechy/proxmox-gpu-passthrough-check/main/proxmox-gpu-passthrough-check.sh | bash -s -- -g -p
```

Check if VM 100 is properly configured for GPU passthrough:
```bash
curl -s https://raw.githubusercontent.com/talltechy/proxmox-gpu-passthrough-check/main/proxmox-gpu-passthrough-check.sh | bash -s -- --vm 100
```

Run both host checks and VM 100 configuration check:
```bash
curl -s https://raw.githubusercontent.com/talltechy/proxmox-gpu-passthrough-check/main/proxmox-gpu-passthrough-check.sh | bash -s -- --all --vm 100
```

Check VM 100 configuration without host checks:
```bash
curl -s https://raw.githubusercontent.com/talltechy/proxmox-gpu-passthrough-check/main/proxmox-gpu-passthrough-check.sh | bash -s -- --vm 100 --skip-host
```

Check all VMs for GPU passthrough configuration:
```bash
curl -s https://raw.githubusercontent.com/talltechy/proxmox-gpu-passthrough-check/main/proxmox-gpu-passthrough-check.sh | bash -s -- --all-vms
```

Generate commands to fix detected issues:
```bash
curl -s https://raw.githubusercontent.com/talltechy/proxmox-gpu-passthrough-check/main/proxmox-gpu-passthrough-check.sh | bash -s -- --generate-fix
```

## Understanding the Output

The script output is organized into sections, each corresponding to a specific check. The results are color-coded for better readability:

- **Green**: SUCCESS - The check passed successfully
- **Yellow**: WARNING - The check identified a potential issue that needs attention
- **Cyan**: INFO - Informational message that provides context or guidance
- **Red**: ERROR - A critical error occurred (rare, usually related to script execution)

At the end of the script, a summary section displays all successful checks and warnings, along with next steps based on the results.

### Host System Checks

The script performs several checks on the host system to verify if it's properly configured for GPU passthrough:

1. **IOMMU in kernel command line**: Checks if IOMMU is enabled in the kernel parameters
2. **IOMMU in dmesg**: Verifies if IOMMU is properly initialized during boot
3. **VFIO modules**: Checks if the required VFIO modules are loaded
4. **IOMMU groups**: Lists all IOMMU groups and highlights those containing GPUs
5. **GPU devices**: Lists all GPU devices and their current drivers
6. **CPU virtualization**: Checks if CPU virtualization features are enabled
7. **Secure Boot**: Verifies if Secure Boot is disabled (recommended for passthrough)
8. **GPU driver blacklisting**: Checks if GPU drivers are properly blacklisted
9. **GPU usage**: Checks if GPUs are in use by the host

### VM Configuration Checks

When using the `--vm` or `--all-vms` options, the script checks VM configurations for GPU passthrough readiness:

1. **Machine type**: Verifies if the VM is using the q35 machine type (recommended for passthrough)
2. **PCI passthrough devices**: Checks if PCI devices are properly configured for passthrough
3. **GPU devices**: Identifies if NVIDIA or AMD GPUs are passed through
4. **ROM file**: Checks if a custom ROM file is configured for the GPU
5. **CPU settings**: Verifies if the CPU 'hidden' state is enabled (helps with GPU reset issues)
6. **OVMF/UEFI firmware**: Checks if the VM is using OVMF/UEFI firmware
7. **Boot parameters**: Checks for helpful boot parameters like 'video=efifb:off'

### Windows-Specific Checks

For Windows VMs, the script performs additional checks specifically for Windows GPU passthrough:

1. **Proxmox Version Detection**:
   - Automatically detects Proxmox version (7.x vs 8.x+)
   - Provides version-specific commands for optimal compatibility
   - Adapts recommendations based on your Proxmox version

2. **Code 43 prevention**: Checks for settings that prevent the common NVIDIA Code 43 error:
   - For Proxmox 8.x+: Uses `-args` parameter with `kvm=off` and `hv_vendor_id=whatever`
   - For Proxmox 7.x and earlier: Uses CPU `hidden=1` parameter and `vendor_id=whatever`
   - Hyper-V enlightenment settings

3. **Performance optimizations**:
   - MSI interrupts configuration (`pcie=1`)
   - Multifunction option for GPU + audio passthrough
   - CPU pinning setup
   - Memory ballooning settings (recommended to disable for gaming)

3. **CPU flags optimization**:
   - Checks for important CPU flags that improve GPU passthrough performance
   - Recommends specific flags based on workload (gaming, productivity)
   - Key flags include: `+pcid`, `+ssse3`, `+sse4_1`, `+sse4_2`, `+aes`
   - These flags ensure optimal performance for GPU-intensive applications

4. **Display settings optimization**:
   - Checks if display is set to 'none' or 'std' (optimal for GPU passthrough)
   - Identifies potential conflicts with SPICE/VNC display settings
   - Recommends optimal display configuration for passthrough scenarios
   - Provides specific commands to update display settings

5. **Hardware compatibility**:
   - x-vga parameter for NVIDIA GPUs
   - ROM file usage for NVIDIA GPUs

6. **Fix recommendations**:
   - Provides specific warnings for missing recommended settings
   - Counts the number of issues found and categorizes them by severity
   - When run with `--generate-fix`, provides exact commands to fix each issue
   - Commands use the Proxmox `qm set` utility to modify VM configuration

### Runtime Checks

When a VM is running, the script can perform additional runtime checks:

1. **VM state detection**: Automatically detects if the VM is running
2. **OS-specific guidance**: Provides different guidance based on Windows vs. Linux VMs
3. **Verification steps**: Lists steps to verify GPU passthrough is working properly:
   - For Windows: Device Manager checks, GPU-Z verification, driver installation
   - For Linux: lspci commands, driver verification, application testing

### Fix Generation

When using the `--generate-fix` option, the script generates commands to fix detected issues:

1. **IOMMU kernel parameters**: Commands to enable IOMMU in GRUB configuration
2. **VFIO modules**: Commands to load and configure VFIO modules
3. **GPU driver blacklisting**: Commands to blacklist GPU drivers and configure VFIO-PCI
4. **VM-specific fixes**: When used with `--vm VMID`, generates VM-specific commands:
   - Detects Proxmox version and provides appropriate commands
   - For Proxmox 8.x+: Uses `-args` parameter with proper syntax
   - For Proxmox 7.x and earlier: Uses traditional CPU parameter syntax
   - Includes commands to add GPU devices to VM
   - Provides commands to disable memory ballooning
   - Includes EFI framebuffer settings for optimal display

## Troubleshooting

If you encounter any issues with the script, try the following:

1. Run the script with root privileges: `sudo bash proxmox-gpu-passthrough-check.sh`
2. Run the script with verbose output: `bash proxmox-gpu-passthrough-check.sh -v`
3. Check if all required dependencies are installed: `apt-get install pciutils lsof`
4. If you're using the one-line execution method and encounter network issues, download the script first and then run it locally

## Next Steps After Running the Script

1. Address any warnings identified by the script
2. Run the script again to verify your changes
3. Once all host system checks pass, configure your VM for GPU passthrough:
   - Add the PCI device to your VM configuration
   - Use the q35 machine type
   - Use OVMF/UEFI firmware
   - For Proxmox 8.x+:
     - Use `-args` parameter with `kvm=off` and `hv_vendor_id=whatever`
     - Add Hyper-V enlightenments for better Windows performance
     - Consider adding EFI framebuffer settings with `video=efifb:off`
   - For Proxmox 7.x and earlier:
     - Set CPU type with 'hidden=1' option
     - Add `vendor_id=whatever` to prevent Code 43 errors
   - Disable memory ballooning for better performance
4. Use the `--vm VMID --generate-fix` options to get exact commands for your VM
5. Test your VM with the passed-through GPU

## Additional Resources

- [Proxmox Wiki: PCI Passthrough](https://pve.proxmox.com/wiki/PCI_Passthrough)
- [Proxmox IOMMU Configuration](https://pve.proxmox.com/wiki/PCI_Passthrough#Verifying_IOMMU_parameters)
- [Proxmox Forum](https://forum.proxmox.com/)
- [GPU Passthrough Guide](https://www.reddit.com/r/homelab/wiki/hardware/pci-passthrough/)
- [AMD Reset Bug Solutions](https://github.com/gnif/vendor-reset)
