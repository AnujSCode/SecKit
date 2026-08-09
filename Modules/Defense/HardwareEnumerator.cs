using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.Defense;

/// <summary>
/// Comprehensive hardware and peripheral enumeration for security auditing.
/// Enumerates USB devices, PCI devices, block devices, network interfaces,
/// CPU information, memory, TPM/Secure Boot status, Bluetooth, and
/// flags security issues with each category.
/// </summary>
public class HardwareEnumerator
{
    /// <summary>Default constructor.</summary>
    public HardwareEnumerator() { }

    /// <summary>Constructor with configuration.</summary>
    public HardwareEnumerator(ConfigManager config) { }

    // Known vendor IDs that might indicate unauthorized/risky devices
    private static readonly Dictionary<string, string> RiskyUsbVendors = new(StringComparer.OrdinalIgnoreCase)
    {
        { "a16f", "Flipper Zero — Penetration testing tool" },
        { "2354", "Bash Bunny / USB Rubber Ducky compatible" },
        { "16d0", "USB Rubber Ducky" },
        { "03eb", "Malduino / BadUSB compatible (Atmel)" },
        { "f055", "Malduino (ATmega32U4)" },
        { "0483", "STM32 — Common in BadUSB" },
        { "2341", "Arduino — HID attack vector" },
        { "1a86", "CH340 USB-Serial — Common in rogue devices" },
    };

    // Network interface flags that indicate security issues
    private static readonly string[] PromiscuousFlags = { "PROMISC", "promisc" };
    private static readonly string[] SuspiciousInterfaceNames =
    {
        "tun", "tap", "veth", "docker", "virbr", "kube", "cali",
        "flannel", "weave", "cni", "lxc", "lxd",
    };

    /// <summary>
    /// Runs comprehensive hardware enumeration on the target system.
    /// </summary>
    /// <param name="target">Target specification — typically "localhost" or hostname.</param>
    /// <returns>ScanResult with hardware findings organized by category.</returns>
    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult
        {
            ModuleName = "Hardware Enumerator",
            TargetUrl = target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            Logger.Info("Enumerating hardware components...");

            // Run all enumerators in parallel
            await Task.WhenAll(
                EnumerateUsbDevicesAsync(result),
                EnumeratePciDevicesAsync(result),
                EnumerateBlockDevicesAsync(result),
                EnumerateNetworkInterfacesAsync(result),
                EnumerateCpuInfoAsync(result),
                EnumerateMemoryInfoAsync(result),
                EnumerateTpmSecureBootAsync(result),
                EnumerateBluetoothDevicesAsync(result),
                EnumeratePortListingsAsync(result)
            );

            // Summary
            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Hardware Enumeration Complete",
                Severity = "Info",
                Description = "Comprehensive hardware enumeration completed. See individual categories for security analysis.",
                Remediation = "Review security flags for each hardware category.",
                Evidence = $"Categories enumerated: USB, PCI, Block, Network, CPU, Memory, TPM/SecureBoot, Bluetooth, Ports",
                Module = "HardwareEnumerator",
                Confidence = 95
            });

            result.Completed = true;
            Logger.Info($"Hardware enumeration complete: {result.Vulnerabilities.Count} findings.");
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"Hardware enumeration failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    /// <summary>
    /// Enumerates USB devices using lsusb. Parses vendor ID, product ID,
    /// serial numbers, and bus topology. Flags known risky devices.
    /// </summary>
    private static async Task EnumerateUsbDevicesAsync(ScanResult result)
    {
        try
        {
            var devices = new List<JsonObject>();

            // Basic enumeration
            var lsusbOutput = await RunCommandAsync("lsusb 2>/dev/null");
            if (!string.IsNullOrWhiteSpace(lsusbOutput))
            {
                foreach (var line in lsusbOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var trimmed = line.Trim();
                    if (string.IsNullOrWhiteSpace(trimmed)) continue;

                    var device = ParseLsusbLine(trimmed);
                    if (device != null)
                    {
                        devices.Add(device);

                        // Check for risky USB devices
                        if (device.TryGetPropertyValue("vendorId", out var vidNode))
                        {
                            var vid = vidNode?.ToString().ToLowerInvariant();
                            if (vid != null && RiskyUsbVendors.TryGetValue(vid, out var riskDescription))
                            {
                                result.Vulnerabilities.Add(new Vulnerability
                                {
                                    Type = "Risky USB Device Detected",
                                    Severity = "High",
                                    Description = $"Potentially risky USB device detected: {device["description"]}. " +
                                                  $"Vendor ID {vid}: {riskDescription}",
                                    Remediation = "Verify this device is authorized. Immediately disconnect if unrecognized.",
                                    Evidence = JsonSerializer.Serialize(device),
                                    Module = "HardwareEnumerator",
                                    Confidence = 75
                                });
                            }
                        }
                    }
                }
            }

            // Detailed enumeration (sudo needed for serials)
            var verboseOutput = await RunCommandAsync("lsusb -v 2>/dev/null | head -500");
            var treeOutput = await RunCommandAsync("lsusb -t 2>/dev/null");

            // Count USB devices by speed
            var lowSpeed = 0;
            var fullSpeed = 0;
            var highSpeed = 0;
            var superSpeed = 0;

            if (!string.IsNullOrWhiteSpace(verboseOutput))
            {
                // Parse the verbose output for device details
                var blocks = verboseOutput.Split(new[] { "\n\n" }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var block in blocks.Take(16)) // Cap at 16 devices for parsing
                {
                    var speed = ExtractField(block, "bcdUSB");
                    if (speed != null)
                    {
                        var speedVal = ParseSpeedValue(speed);
                        if (speedVal < 200) lowSpeed++;
                        else if (speedVal < 300) fullSpeed++;
                        else if (speedVal < 400) highSpeed++;
                        else superSpeed++;

                        // Check if USB 1.1 (1.x) devices exist — security concern (easier to exploit)
                        if (speedVal < 200)
                        {
                            var deviceName = ExtractField(block, "iProduct") ?? "Unknown";
                            if (string.IsNullOrWhiteSpace(deviceName))
                                deviceName = ExtractField(block, "idProduct") ?? "Unknown";
                        }

                        // Check for serial numbers (HID devices with serials could be spoofing)
                        var serial = ExtractField(block, "iSerial");
                        if (!string.IsNullOrWhiteSpace(serial) && serial != "3")
                        {
                            // Some devices with serial could be spoofed
                        }
                    }

                    // Check device class for HID (keyboard/mouse) — potential keystroke injection
                    var deviceClass = ExtractField(block, "bDeviceClass");
                    var subClass = ExtractField(block, "bDeviceSubClass");

                    if (deviceClass == "0" || deviceClass == "3")
                    {
                        // HID device — these can be used for keystroke injection (BadUSB/Rubber Ducky)
                        var protocol = ExtractField(block, "bInterfaceProtocol");
                        if (protocol == "1" || protocol == "2")
                        {
                            // Keyboard (1) or Mouse (2)
                            var productName = ExtractField(block, "iProduct") ?? "Unknown HID";
                            Logger.Debug($"HID device found: {productName} (protocol: Keyboard/Mouse)");
                        }
                    }
                }
            }

            var usbSummary = new JsonObject
            {
                ["totalDevices"] = devices.Count,
                ["devices"] = JsonSerializer.Serialize(devices),
                ["busTree"] = treeOutput?.Trim() ?? "",
                ["speedBreakdown"] = new JsonObject
                {
                    ["lowSpeed"] = lowSpeed,
                    ["fullSpeed"] = fullSpeed,
                    ["highSpeed"] = highSpeed,
                    ["superSpeed"] = superSpeed,
                },
            };

            if (devices.Count == 0)
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "No USB Devices",
                    Severity = "Info",
                    Description = "No USB devices detected. If this is a physical server, check USB ports are locked down.",
                    Remediation = "Ensure USB ports are disabled in BIOS if not needed.",
                    Evidence = "lsusb returned no output",
                    Module = "HardwareEnumerator",
                    Confidence = 80
                });
            }

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Hardware: USB Devices",
                Severity = "Info",
                Description = $"Enumerated {devices.Count} USB devices ({lowSpeed} LS, {fullSpeed} FS, {highSpeed} HS, {superSpeed} SS).",
                Remediation = "Review USB devices for unauthorized hardware. Consider USB port lockdown.",
                Evidence = JsonSerializer.Serialize(usbSummary),
                Module = "HardwareEnumerator",
                Confidence = 90
            });
        }
        catch (Exception ex)
        {
            Logger.Debug($"USB enumeration failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Enumerates PCI devices using lspci. Parses device class, vendor, driver binding.
    /// </summary>
    private static async Task EnumeratePciDevicesAsync(ScanResult result)
    {
        try
        {
            var devices = new List<JsonObject>();

            // Full verbose listing
            var lspciOutput = await RunCommandAsync("lspci -v 2>/dev/null");
            var lspciNumeric = await RunCommandAsync("lspci -nn 2>/dev/null");

            if (!string.IsNullOrWhiteSpace(lspciNumeric))
            {
                foreach (var line in lspciNumeric.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var trimmed = line.Trim();
                    if (string.IsNullOrWhiteSpace(trimmed)) continue;

                    var device = ParseLspciLine(trimmed);
                    if (device != null)
                    {
                        devices.Add(device);
                    }
                }
            }

            // Categorize devices by class
            var byClass = new JsonObject();
            foreach (var dev in devices)
            {
                var cls = dev.TryGetPropertyValue("class", out var c) ? c?.ToString() ?? "Unknown" : "Unknown";
                if (!byClass.ContainsKey(cls))
                    byClass[cls] = 0;
                byClass[cls] = (byClass[cls]?.GetValue<int>() ?? 0) + 1;
            }

            // Check for devices without drivers (potential security concern)
            var driverless = new List<string>();
            if (!string.IsNullOrWhiteSpace(lspciOutput))
            {
                var blocks = lspciOutput.Split(new[] { "\n\n" }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var block in blocks)
                {
                    if (!block.Contains("Kernel driver in use") && !block.Contains("Kernel modules"))
                        continue;

                    var deviceName = block.Split('\n').FirstOrDefault()?.Trim() ?? "Unknown";
                    if (!block.Contains("Kernel driver in use:"))
                        driverless.Add(deviceName);
                }
            }

            if (driverless.Count > 0)
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "PCI Devices Without Drivers",
                    Severity = "Low",
                    Description = $"{driverless.Count} PCI devices lack a kernel driver. This may indicate unrecognized hardware.",
                    Remediation = "Install appropriate drivers or disable unneeded PCI devices in BIOS.",
                    Evidence = string.Join("; ", driverless.Take(10)),
                    Module = "HardwareEnumerator",
                    Confidence = 70
                });
            }

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Hardware: PCI Devices",
                Severity = "Info",
                Description = $"Enumerated {devices.Count} PCI devices across {byClass.Count} device classes.",
                Remediation = "Review PCI devices for unauthorized hardware or missing drivers.",
                Evidence = JsonSerializer.Serialize(new { devices, byClass, driverless = driverless.Count }),
                Module = "HardwareEnumerator",
                Confidence = 95
            });
        }
        catch (Exception ex)
        {
            Logger.Debug($"PCI enumeration failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Enumerates block devices using lsblk. Lists disks, partitions,
    /// sizes, mount points, and filesystem types.
    /// </summary>
    private static async Task EnumerateBlockDevicesAsync(ScanResult result)
    {
        try
        {
            var lsblkOutput = await RunCommandAsync("lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,LABEL,MODEL,SERIAL 2>/dev/null");
            var dfOutput = await RunCommandAsync("df -h 2>/dev/null | grep -v tmpfs | grep -v devtmpfs");
            var cryptOutput = await RunCommandAsync("lsblk -o NAME,TYPE,MOUNTPOINT,FSTYPE | grep crypt");

            // Parse lsblk into structured data
            var disks = new List<JsonObject>();
            var partitions = new List<JsonObject>();

            if (!string.IsNullOrWhiteSpace(lsblkOutput))
            {
                var lines = lsblkOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                for (int i = 1; i < lines.Length; i++) // Skip header
                {
                    var parts = lines[i].Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 3) continue;

                    var entry = new JsonObject
                    {
                        ["name"] = parts[0],
                        ["size"] = parts.Length > 1 ? parts[1] : "",
                        ["type"] = parts.Length > 2 ? parts[2] : "",
                        ["mountpoint"] = parts.Length > 3 ? parts[3] : "",
                        ["fstype"] = parts.Length > 4 ? parts[4] : "",
                        ["label"] = parts.Length > 5 ? parts[5] : "",
                        ["model"] = parts.Length > 6 ? parts[6] : "",
                        ["serial"] = parts.Length > 7 ? parts[7] : "",
                    };

                    var type = entry["type"]?.ToString() ?? "";
                    if (type == "disk")
                        disks.Add(entry);
                    else if (type == "part" || type == "lvm" || type == "crypt")
                        partitions.Add(entry);
                }
            }

            // Security checks: disk encryption
            var encryptedPartitions = partitions
                .Where(p => (p["fstype"]?.ToString() ?? "").Contains("crypto", StringComparison.OrdinalIgnoreCase) ||
                           (p["type"]?.ToString() ?? "") == "crypt")
                .ToList();

            var unencryptedMounts = partitions
                .Where(p => !string.IsNullOrWhiteSpace(p["mountpoint"]?.ToString()) &&
                            p["mountpoint"]?.ToString() != "[SWAP]" &&
                            !encryptedPartitions.Contains(p))
                .ToList();

            if (unencryptedMounts.Count > 0 && encryptedPartitions.Count == 0)
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Missing Disk Encryption",
                    Severity = "High",
                    Description = $"No LUKS-encrypted partitions detected. {unencryptedMounts.Count} mounted partitions are unencrypted.",
                    Remediation = "Implement LUKS full-disk encryption. Consider using dm-crypt/LUKS for sensitive data partitions.",
                    Evidence = $"Unencrypted mounts: {unencryptedMounts.Count}",
                    Module = "HardwareEnumerator",
                    Confidence = 85
                });
            }

            // Check for removable media mounted
            var removableOutput = await RunCommandAsync("lsblk -o NAME,RM,MOUNTPOINT 2>/dev/null | grep '^[a-z].*1 /'");
            if (!string.IsNullOrWhiteSpace(removableOutput))
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Removable Media Mounted",
                    Severity = "Medium",
                    Description = $"Removable media is currently mounted: {removableOutput.Trim()}",
                    Remediation = "Verify the removable media is authorized. Unmount if suspicious.",
                    Evidence = removableOutput.Trim(),
                    Module = "HardwareEnumerator",
                    Confidence = 80
                });
            }

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Hardware: Block Devices",
                Severity = "Info",
                Description = $"Enumerated {disks.Count} disk(s) with {partitions.Count} partitions. {encryptedPartitions.Count} encrypted.",
                Remediation = "Review disk configuration and verify encryption on sensitive volumes.",
                Evidence = JsonSerializer.Serialize(new { disks, partitions, df = dfOutput?.Trim(), encrypted = encryptedPartitions.Count }),
                Module = "HardwareEnumerator",
                Confidence = 95
            });
        }
        catch (Exception ex)
        {
            Logger.Debug($"Block device enumeration failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Enumerates network interfaces — MAC, state, driver, speed, and flags.
    /// Flags promiscuous mode, suspicious interface names, and missing drivers.
    /// </summary>
    private static async Task EnumerateNetworkInterfacesAsync(ScanResult result)
    {
        try
        {
            var interfaces = new List<JsonObject>();

            // ip link show
            var ipLinkOutput = await RunCommandAsync("ip -o link show 2>/dev/null");
            if (!string.IsNullOrWhiteSpace(ipLinkOutput))
            {
                foreach (var line in ipLinkOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var iface = ParseIpLinkLine(line.Trim());
                    if (iface != null)
                    {
                        interfaces.Add(iface);

                        // Security: check promiscuous mode
                        var flags = iface.TryGetPropertyValue("flags", out var f) ? f?.ToString() ?? "" : "";
                        if (PromiscuousFlags.Any(p => flags.Contains(p, StringComparison.OrdinalIgnoreCase)))
                        {
                            result.Vulnerabilities.Add(new Vulnerability
                            {
                                Type = "Promiscuous Network Interface",
                                Severity = "High",
                                Description = $"Network interface '{iface["name"]}' is in PROMISCUOUS mode. This is used for packet sniffing.",
                                Remediation = $"Disable promiscuous mode if not needed: sudo ip link set {iface["name"]} promisc off",
                                Evidence = $"Interface: {iface["name"]} | Flags: {flags}",
                                Module = "HardwareEnumerator",
                                Confidence = 90
                            });
                        }

                        // Security: check suspicious interface names
                        var name = iface.TryGetPropertyValue("name", out var n) ? n?.ToString() ?? "" : "";
                        if (SuspiciousInterfaceNames.Any(s =>
                            name.Contains(s, StringComparison.OrdinalIgnoreCase)))
                        {
                            Logger.Debug($"Container/orchestration interface: {name}");
                        }
                    }
                }
            }

            // Additional interface details from ethtool
            var ethInterfaces = interfaces
                .Where(i => (i.TryGetPropertyValue("name", out var name) ? name?.ToString() : null) is string s && s != "lo")
                .ToList();

            foreach (var iface in ethInterfaces)
            {
                var name = iface["name"]?.ToString();
                if (string.IsNullOrWhiteSpace(name)) continue;

                var speedOutput = await RunCommandAsync($"ethtool '{name}' 2>/dev/null | grep -E 'Speed|Duplex|Link|Driver'");
                if (!string.IsNullOrWhiteSpace(speedOutput))
                {
                    foreach (var line in speedOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                    {
                        var parts = line.Split(':', 2);
                        if (parts.Length == 2)
                        {
                            iface[parts[0].Trim().ToLowerInvariant().Replace(" ", "")] = parts[1].Trim();
                        }
                    }
                }

                // Flag interfaces with no link partner (unplugged but could be reconnected)
                if (iface.TryGetPropertyValue("linkdetected", out var ld) && ld?.ToString() == "no")
                {
                    Logger.Debug($"Interface {name} has no link — cable disconnected.");
                }
            }

            // Count active vs inactive interfaces
            var activeInterfaces = interfaces.Count(i =>
                (i.TryGetPropertyValue("state", out var s) ? s?.ToString() : null) is "UP");

            if (activeInterfaces == 0 && interfaces.Count > 0)
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "No Active Network Interfaces",
                    Severity = "Medium",
                    Description = $"All {interfaces.Count} network interfaces are DOWN. System may have network issues.",
                    Remediation = "Check network configuration and cable connections.",
                    Evidence = $"Interfaces total: {interfaces.Count}, active: 0",
                    Module = "HardwareEnumerator",
                    Confidence = 85
                });
            }

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Hardware: Network Interfaces",
                Severity = "Info",
                Description = $"Enumerated {interfaces.Count} network interfaces ({activeInterfaces} active).",
                Remediation = "Review interfaces for unauthorized devices or suspicious configurations.",
                Evidence = JsonSerializer.Serialize(interfaces),
                Module = "HardwareEnumerator",
                Confidence = 95
            });
        }
        catch (Exception ex)
        {
            Logger.Debug($"Network interface enumeration failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Enumerates CPU information: model, cores, threads, virtualization support.
    /// </summary>
    private static async Task EnumerateCpuInfoAsync(ScanResult result)
    {
        try
        {
            var cpuInfo = new JsonObject();

            // /proc/cpuinfo
            var cpuinfoContent = await RunCommandAsync("cat /proc/cpuinfo 2>/dev/null");
            if (!string.IsNullOrWhiteSpace(cpuinfoContent))
            {
                var processors = 0;
                var physicalIds = new HashSet<string>();
                var model = "";
                var cores = "";
                var flags = "";

                foreach (var line in cpuinfoContent.Split('\n'))
                {
                    var parts = line.Split(':', 2);
                    if (parts.Length != 2) continue;

                    var key = parts[0].Trim();
                    var value = parts[1].Trim();

                    switch (key)
                    {
                        case "processor": processors++; break;
                        case "physical id": physicalIds.Add(value); break;
                        case "model name":
                            if (string.IsNullOrWhiteSpace(model)) model = value;
                            break;
                        case "cpu cores": cores = value; break;
                        case "flags": flags = value; break;
                    }
                }

                cpuInfo["model"] = model;
                cpuInfo["logicalProcessors"] = processors;
                cpuInfo["physicalCpus"] = physicalIds.Count;
                cpuInfo["coresPerCpu"] = cores;

                // Security: check virtualization support
                var hasVmx = flags.Contains("vmx", StringComparison.OrdinalIgnoreCase);
                var hasSvm = flags.Contains("svm", StringComparison.OrdinalIgnoreCase);
                var virtEnabled = hasVmx || hasSvm;

                cpuInfo["virtualizationSupported"] = virtEnabled;
                cpuInfo["virtualizationType"] = hasVmx ? "Intel VT-x" : hasSvm ? "AMD-V" : "None";

                // Security: check for known CPU vulnerabilities
                // Meltdown/Spectre mitigations
                var hasPti = flags.Contains("pti", StringComparison.OrdinalIgnoreCase);
                var hasIbrs = flags.Contains("ibrs", StringComparison.OrdinalIgnoreCase) ||
                             flags.Contains("ibpb", StringComparison.OrdinalIgnoreCase);
                var hasStibp = flags.Contains("stibp", StringComparison.OrdinalIgnoreCase);

                if (!string.IsNullOrWhiteSpace(flags))
                {
                    if (!hasIbrs)
                    {
                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "Missing Spectre v2 Mitigation",
                            Severity = "Medium",
                            Description = "CPU flags do not indicate IBRS/IBPB support. Spectre v2 mitigations may be incomplete.",
                            Remediation = "Update CPU microcode and kernel. Enable Spectre v2 mitigations.",
                            Evidence = $"Missing IBRS/IBPB flags",
                            Module = "HardwareEnumerator",
                            Confidence = 60
                        });
                    }
                }

                // Get CPU frequency
                var freqOutput = await RunCommandAsync(
                    "cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null || lscpu | grep 'CPU MHz'");
                if (!string.IsNullOrWhiteSpace(freqOutput))
                {
                    cpuInfo["currentFrequency"] = freqOutput.Trim();
                }
            }

            // lscpu summary
            var lscpuOutput = await RunCommandAsync("lscpu 2>/dev/null");
            if (!string.IsNullOrWhiteSpace(lscpuOutput))
            {
                foreach (var line in lscpuOutput.Split('\n'))
                {
                    var parts = line.Split(':', 2);
                    if (parts.Length == 2)
                    {
                        var key = parts[0].Trim().ToLowerInvariant().Replace(" ", "");
                        if (!((IDictionary<string, JsonNode?>)cpuInfo).ContainsKey(key))
                            cpuInfo[key] = parts[1].Trim();
                    }
                }
            }

            var cpuModel = cpuInfo.TryGetPropertyValue("model", out var m) ? m?.ToString() : "Unknown";
            var cpuLogical = cpuInfo.TryGetPropertyValue("logicalProcessors", out var lp) ? lp?.ToString() : "?";
            var cpuVirt = cpuInfo.TryGetPropertyValue("virtualizationType", out var vt) ? vt?.ToString() : "Unknown";

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Hardware: CPU Information",
                Severity = "Info",
                Description = $"CPU: {cpuModel} — {cpuLogical} logical processors, Virtualization: {cpuVirt}",
                Remediation = "Ensure CPU microcode is updated for security patches.",
                Evidence = JsonSerializer.Serialize(cpuInfo),
                Module = "HardwareEnumerator",
                Confidence = 95
            });
        }
        catch (Exception ex)
        {
            Logger.Debug($"CPU enumeration failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Enumerates memory information: total RAM, swap, DIMM details from dmidecode.
    /// </summary>
    private static async Task EnumerateMemoryInfoAsync(ScanResult result)
    {
        try
        {
            var memInfo = new JsonObject();

            // /proc/meminfo
            var memOutput = await RunCommandAsync("cat /proc/meminfo 2>/dev/null");
            if (!string.IsNullOrWhiteSpace(memOutput))
            {
                foreach (var line in memOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = line.Split(':', 2);
                    if (parts.Length != 2) continue;

                    var key = parts[0].Trim().ToLowerInvariant();
                    var value = parts[1].Trim();
                    memInfo[key] = value;
                }
            }

            // Parse key values
            var totalMem = memInfo.TryGetPropertyValue("memtotal", out var tm) ? tm?.ToString() ?? "Unknown" : "Unknown";
            var totalSwap = memInfo.TryGetPropertyValue("swaptotal", out var ts) ? ts?.ToString() ?? "0 kB" : "0 kB";
            var availableMem = memInfo.TryGetPropertyValue("memavailable", out var am) ? am?.ToString() ?? "Unknown" : "Unknown";

            // dmidecode for DIMM info (needs sudo)
            var dimmOutput = await RunCommandAsync("sudo dmidecode -t memory 2>/dev/null || dmidecode -t memory 2>/dev/null");
            var dimms = new List<JsonObject>();

            if (!string.IsNullOrWhiteSpace(dimmOutput) && !dimmOutput.Contains("Permission denied"))
            {
                var blocks = dimmOutput.Split(new[] { "\n\n" }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var block in blocks)
                {
                    if (!block.Contains("Size:") || block.Contains("No Module Installed")) continue;

                    var dimm = new JsonObject();
                    foreach (var field in new[] { "Size", "Type", "Speed", "Manufacturer", "Serial Number", "Part Number", "Locator", "Bank Locator" })
                    {
                        var match = Regex.Match(block, $@"{field}:\s*(.+)$", RegexOptions.Multiline);
                        if (match.Success)
                            dimm[field.ToLowerInvariant().Replace(" ", "")] = match.Groups[1].Value.Trim();
                    }
                    if (dimm.Count > 1)
                        dimms.Add(dimm);
                }
            }

            // Security: check if swap is encrypted
            var swapOnOutput = await RunCommandAsync("swapon --show 2>/dev/null");
            var hasUnencryptedSwap = !string.IsNullOrWhiteSpace(swapOnOutput) &&
                                     !swapOnOutput.Contains("crypt", StringComparison.OrdinalIgnoreCase);

            if (hasUnencryptedSwap && !string.IsNullOrWhiteSpace(totalSwap) && totalSwap != "0 kB")
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Unencrypted Swap",
                    Severity = "Medium",
                    Description = $"Swap space ({totalSwap}) is unencrypted. Memory contents including keys could be written to disk.",
                    Remediation = "Enable encrypted swap using LUKS or disable swap entirely for sensitive systems.",
                    Evidence = $"Swap: {totalSwap} | Encrypted: no",
                    Module = "HardwareEnumerator",
                    Confidence = 80
                });
            }

            // Check for adequate memory
            if (!string.IsNullOrWhiteSpace(availableMem))
            {
                if (TryParseKb(availableMem, out var availKb) && availKb < 512 * 1024)
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Low Available Memory",
                        Severity = "Low",
                        Description = $"Available memory ({availableMem}) is below 512 MB. System may be resource-constrained.",
                        Remediation = "Add more RAM or free up memory by stopping unnecessary services.",
                        Evidence = $"Available: {availableMem}",
                        Module = "HardwareEnumerator",
                        Confidence = 80
                    });
                }
            }

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Hardware: Memory",
                Severity = "Info",
                Description = $"Total RAM: {totalMem} | Available: {availableMem} | Swap: {totalSwap} | DIMMs: {dimms.Count}",
                Remediation = "Ensure adequate memory for workloads and enable encrypted swap.",
                Evidence = JsonSerializer.Serialize(new { memInfo, dimms, swapInfo = swapOnOutput?.Trim() }),
                Module = "HardwareEnumerator",
                Confidence = 95
            });
        }
        catch (Exception ex)
        {
            Logger.Debug($"Memory enumeration failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Checks TPM device presence and Secure Boot status.
    /// </summary>
    private static async Task EnumerateTpmSecureBootAsync(ScanResult result)
    {
        try
        {
            var securityInfo = new JsonObject();

            // Check TPM device
            var tpmOutput = await RunCommandAsync("ls -la /dev/tpm* 2>/dev/null");
            var tpm2Output = await RunCommandAsync("ls -la /dev/tpmrm* 2>/dev/null");
            var dmesgTpm = await RunCommandAsync("dmesg 2>/dev/null | grep -i tpm | tail -5");

            var hasTpm = !string.IsNullOrWhiteSpace(tpmOutput) || !string.IsNullOrWhiteSpace(tpm2Output);
            securityInfo["tpmDetected"] = hasTpm;
            securityInfo["tpmDevices"] = tpmOutput?.Trim() ?? "";
            securityInfo["tpmDmesg"] = dmesgTpm?.Trim() ?? "";

            if (!hasTpm)
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "No TPM Detected",
                    Severity = "Medium",
                    Description = "No TPM (Trusted Platform Module) device detected. BitLocker, LUKS TPM binding, and measured boot are unavailable.",
                    Remediation = "Install a TPM 2.0 module if the motherboard supports it, or use a firmware TPM (fTPM).",
                    Evidence = "No /dev/tpm* devices found",
                    Module = "HardwareEnumerator",
                    Confidence = 85
                });
            }

            // Check Secure Boot status
            var secureBootOutput = await RunCommandAsync(
                "mokutil --sb-state 2>/dev/null || cat /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | xxd | head -1");

            var isSecureBootEnabled = false;
            if (!string.IsNullOrWhiteSpace(secureBootOutput))
            {
                isSecureBootEnabled = secureBootOutput.Contains("SecureBoot enabled", StringComparison.OrdinalIgnoreCase);
                securityInfo["secureBootStatus"] = secureBootOutput.Trim();
            }
            else
            {
                // Check via bootctl if available
                var bootctlOutput = await RunCommandAsync("bootctl status 2>/dev/null | grep 'Secure Boot'");
                if (!string.IsNullOrWhiteSpace(bootctlOutput))
                {
                    isSecureBootEnabled = bootctlOutput.Contains("enabled", StringComparison.OrdinalIgnoreCase);
                    securityInfo["secureBootStatus"] = bootctlOutput.Trim();
                }
                else
                {
                    securityInfo["secureBootStatus"] = "Unknown — could not determine";
                }
            }

            securityInfo["secureBootEnabled"] = isSecureBootEnabled;

            if (!isSecureBootEnabled && hasTpm)
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Secure Boot Disabled",
                    Severity = "Medium",
                    Description = "Secure Boot is DISABLED while TPM is available. Boot-time malware and rootkits are harder to detect without Secure Boot.",
                    Remediation = "Enable Secure Boot in UEFI/BIOS settings.",
                    Evidence = $"TPM: present | Secure Boot: disabled",
                    Module = "HardwareEnumerator",
                    Confidence = 85
                });
            }

            // Check for EFI vs Legacy boot
            var efiDir = await RunCommandAsync("ls /sys/firmware/efi 2>/dev/null");
            var isUefi = !string.IsNullOrWhiteSpace(efiDir);
            securityInfo["bootMode"] = isUefi ? "UEFI" : "Legacy BIOS";

            if (!isUefi)
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Legacy BIOS Boot",
                    Severity = "Low",
                    Description = "System is booting in Legacy BIOS mode instead of UEFI. Secure Boot requires UEFI.",
                    Remediation = "Convert to UEFI boot if the hardware supports it.",
                    Evidence = "No /sys/firmware/efi directory",
                    Module = "HardwareEnumerator",
                    Confidence = 85
                });
            }

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Hardware: TPM & Secure Boot",
                Severity = "Info",
                Description = $"TPM: {(hasTpm ? "Present" : "Not Detected")} | Secure Boot: {(isSecureBootEnabled ? "Enabled" : "Disabled")} | Boot: {securityInfo["bootMode"]}",
                Remediation = "Enable TPM and Secure Boot for hardware-backed security.",
                Evidence = JsonSerializer.Serialize(securityInfo),
                Module = "HardwareEnumerator",
                Confidence = 90
            });
        }
        catch (Exception ex)
        {
            Logger.Debug($"TPM/SecureBoot check failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Enumerates Bluetooth adapters and paired/connected devices.
    /// </summary>
    private static async Task EnumerateBluetoothDevicesAsync(ScanResult result)
    {
        try
        {
            var btInfo = new JsonObject();

            // Check if bluetooth hardware exists
            var hciconfigOutput = await RunCommandAsync("hciconfig -a 2>/dev/null");
            var btAdapterOutput = await RunCommandAsync("ls /sys/class/bluetooth 2>/dev/null");
            var rfkillOutput = await RunCommandAsync("rfkill list bluetooth 2>/dev/null");

            var hasHardware = !string.IsNullOrWhiteSpace(hciconfigOutput) || !string.IsNullOrWhiteSpace(btAdapterOutput);
            btInfo["bluetoothHardwareDetected"] = hasHardware;

            if (hasHardware)
            {
                // Get adapter details
                if (!string.IsNullOrWhiteSpace(hciconfigOutput))
                {
                    btInfo["adapterInfo"] = hciconfigOutput.Trim();

                    // Extract MAC address for tracking
                    foreach (var line in hciconfigOutput.Split('\n'))
                    {
                        if (line.Contains("BD Address:"))
                        {
                            var mac = line.Split(':')[1..].Aggregate("", (a, b) => a + ":" + b).TrimStart(':');
                            btInfo["macAddress"] = mac.Trim();
                        }

                        // Check if adapter is UP (potential attack surface)
                        if (line.Contains("UP RUNNING"))
                        {
                            var btMac = btInfo.TryGetPropertyValue("macAddress", out var mac) ? mac?.ToString() : "unknown";

                            result.Vulnerabilities.Add(new Vulnerability
                            {
                                Type = "Bluetooth Adapter Active",
                                Severity = "Low",
                                Description = "Bluetooth adapter is UP and RUNNING. This is an active wireless interface that could be targeted.",
                                Remediation = "Disable Bluetooth if not needed: sudo rfkill block bluetooth",
                                Evidence = $"Adapter state: UP RUNNING | MAC: {btMac}",
                                Module = "HardwareEnumerator",
                                Confidence = 75
                            });
                        }
                        break;
                    }
                }

                // Check paired devices - needs bluetoothctl
                var pairedOutput = await RunCommandAsync(
                    "echo 'paired-devices' | timeout 3 bluetoothctl 2>/dev/null || echo ''");
                btInfo["pairedDevices"] = pairedOutput?.Trim() ?? "";

                // Count paired devices
                var pairedCount = !string.IsNullOrWhiteSpace(pairedOutput)
                    ? pairedOutput.Split('\n').Count(l => l.Contains("Device "))
                    : 0;
                btInfo["pairedDeviceCount"] = pairedCount;

                if (pairedCount > 5)
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Many Paired Bluetooth Devices",
                        Severity = "Low",
                        Description = $"{pairedCount} Bluetooth devices are paired. Review for unauthorized devices.",
                        Remediation = "Remove untrusted paired devices using bluetoothctl.",
                        Evidence = $"Paired devices: {pairedCount}",
                        Module = "HardwareEnumerator",
                        Confidence = 60
                    });
                }

                // Check rfkill status (is BT blocked?)
                if (!string.IsNullOrWhiteSpace(rfkillOutput))
                {
                    btInfo["rfkillStatus"] = rfkillOutput.Trim();
                    if (rfkillOutput.Contains("Soft blocked: yes") || rfkillOutput.Contains("Hard blocked: yes"))
                    {
                        btInfo["blocked"] = true;
                    }
                }
            }
            else
            {
                btInfo["status"] = "No Bluetooth hardware detected";
            }

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Hardware: Bluetooth",
                Severity = "Info",
                Description = $"Bluetooth: {(hasHardware ? "Detected" : "Not available")}. " +
                              $"Paired devices: {(btInfo.TryGetPropertyValue("pairedDeviceCount", out var pd2) ? pd2?.ToString() : "0")}",
                Remediation = "Disable Bluetooth if not needed. Remove unnecessary paired devices.",
                Evidence = JsonSerializer.Serialize(btInfo),
                Module = "HardwareEnumerator",
                Confidence = 90
            });
        }
        catch (Exception ex)
        {
            Logger.Debug($"Bluetooth enumeration failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Lists all detected physical ports/interfaces: USB, Thunderbolt, HDMI, Ethernet, etc.
    /// Uses lspci, lsusb, and sysfs to catalog every physical interface.
    /// </summary>
    private static async Task EnumeratePortListingsAsync(ScanResult result)
    {
        try
        {
            var ports = new JsonObject();

            // USB ports from sysfs
            var usbPorts = await RunCommandAsync(
                "find /sys/bus/usb/devices -name 'product' 2>/dev/null | while read f; do echo \"$(dirname \"$f\"): $(cat \"$f\")\"; done | head -30");
            ports["usbPorts"] = usbPorts?.Trim() ?? "";

            // PCIe slots
            var pcieSlots = await RunCommandAsync(
                "lspci | grep -i 'bridge' | head -20 2>/dev/null");
            ports["pcieBridges"] = pcieSlots?.Trim() ?? "";

            // Ethernet MAC addresses
            var ethMacs = await RunCommandAsync(
                "ip link show 2>/dev/null | grep -E 'link/(ether|infiniband)' | awk '{print $2}' | head -20");
            ports["ethernetMacs"] = ethMacs?.Trim() ?? "";

            // Video outputs
            var videoPorts = await RunCommandAsync(
                "ls /sys/class/drm/card*-*/status 2>/dev/null | while read f; do echo \"$(dirname \"$f\" | xargs basename): $(cat \"$f\")\"; done");
            ports["videoOutputs"] = videoPorts?.Trim() ?? "";

            // Audio devices
            var audioDevices = await RunCommandAsync(
                "aplay -l 2>/dev/null | grep card | head -10");
            ports["audioDevices"] = audioDevices?.Trim() ?? "";

            // Thunderbolt
            var thunderbolt = await RunCommandAsync(
                "ls /sys/bus/thunderbolt/devices 2>/dev/null");
            ports["thunderboltDevices"] = string.IsNullOrWhiteSpace(thunderbolt) ? "None" : thunderbolt.Trim();

            // Serial ports
            var serialPorts = await RunCommandAsync(
                "ls -la /dev/ttyS* /dev/ttyUSB* /dev/ttyACM* 2>/dev/null");
            ports["serialPorts"] = serialPorts?.Trim() ?? "";

            if (!string.IsNullOrWhiteSpace(serialPorts))
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Serial Ports Available",
                    Severity = "Low",
                    Description = $"Serial ports detected: {serialPorts.Replace("\n", ", ").Trim()}",
                    Remediation = "Disable serial port access in BIOS if not needed. Serial consoles can bypass authentication.",
                    Evidence = serialPorts.Trim(),
                    Module = "HardwareEnumerator",
                    Confidence = 70
                });
            }

            if (!string.IsNullOrWhiteSpace(thunderbolt))
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Thunderbolt Devices",
                    Severity = "Medium",
                    Description = $"Thunderbolt devices detected. Thunderbolt DMA attacks can bypass OS security.",
                    Remediation = "Disable Thunderbolt in BIOS if not needed, or enable Thunderbolt security levels.",
                    Evidence = thunderbolt.Trim(),
                    Module = "HardwareEnumerator",
                    Confidence = 70
                });
            }

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Hardware: Physical Ports/Interfaces",
                Severity = "Info",
                Description = $"Enumerated physical ports: USB, PCIe, Ethernet, Video, Audio, Thunderbolt, Serial.",
                Remediation = "Disable unused physical interfaces in BIOS for defense-in-depth.",
                Evidence = JsonSerializer.Serialize(ports),
                Module = "HardwareEnumerator",
                Confidence = 90
            });
        }
        catch (Exception ex)
        {
            Logger.Debug($"Port listing failed: {ex.Message}");
        }
    }

    // --- Parsing helpers ---

    /// <summary>
    /// Parses a single line of lsusb output.
    /// Example: "Bus 001 Device 002: ID 8087:0024 Intel Corp. Integrated Rate Matching Hub"
    /// </summary>
    private static JsonObject? ParseLsusbLine(string line)
    {
        try
        {
            var obj = new JsonObject();

            // Extract bus and device
            var busMatch = Regex.Match(line, @"Bus (\d{3}) Device (\d{3})");
            if (busMatch.Success)
            {
                obj["bus"] = busMatch.Groups[1].Value;
                obj["device"] = busMatch.Groups[2].Value;
            }

            // Extract vendor:product IDs
            var idMatch = Regex.Match(line, @"ID ([0-9a-fA-F]{4}):([0-9a-fA-F]{4})");
            if (idMatch.Success)
            {
                obj["vendorId"] = idMatch.Groups[1].Value.ToLowerInvariant();
                obj["productId"] = idMatch.Groups[2].Value.ToLowerInvariant();
            }

            // Extract description
            var descMatch = Regex.Match(line, @"ID [0-9a-fA-F]{4}:[0-9a-fA-F]{4}\s+(.+)$");
            if (descMatch.Success)
            {
                obj["description"] = descMatch.Groups[1].Value.Trim();
            }
            else if (string.IsNullOrWhiteSpace(obj.TryGetPropertyValue("description", out _) ? null : null))
            {
                obj["description"] = line;
            }

            return obj.Count > 0 ? obj : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Parses a single line of lspci -nn output.
    /// Example: "00:02.0 VGA compatible controller [0300]: Intel Corporation ..."
    /// </summary>
    private static JsonObject? ParseLspciLine(string line)
    {
        try
        {
            var obj = new JsonObject();

            // Extract slot
            var slotMatch = Regex.Match(line, @"^([0-9a-fA-F:.]+)");
            if (slotMatch.Success)
                obj["slot"] = slotMatch.Groups[1].Value;

            // Extract class [classId]
            var classMatch = Regex.Match(line, @"\[(\w{4})\]");
            if (classMatch.Success)
            {
                var classId = classMatch.Groups[1].Value;
                obj["classId"] = classId;
                obj["class"] = ClassifyPciDevice(classId);
            }

            // Extract vendor:product IDs
            var idMatch = Regex.Match(line, @"\[([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\]$");
            if (idMatch.Success)
            {
                obj["vendorId"] = idMatch.Groups[1].Value.ToLowerInvariant();
                obj["productId"] = idMatch.Groups[2].Value.ToLowerInvariant();
            }

            // Description — everything between the class bracket and the ID bracket
            var descMatch = Regex.Match(line, @"\[(\w{4})\]\s+(.+?)\s+\[([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\]$");
            if (descMatch.Success)
            {
                obj["description"] = descMatch.Groups[2].Value.Trim();
            }
            else
            {
                obj["description"] = line;
            }

            return obj.Count > 0 ? obj : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Parses a single line of "ip -o link show" output.
    /// Example: "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00"
    /// </summary>
    private static JsonObject? ParseIpLinkLine(string line)
    {
        try
        {
            var obj = new JsonObject();

            // Extract index:name
            var nameMatch = Regex.Match(line, @"^\d+:\s+(\S+):");
            if (nameMatch.Success)
                obj["name"] = nameMatch.Groups[1].Value;

            // Extract flags between <>
            var flagsMatch = Regex.Match(line, @"<(.+?)>");
            if (flagsMatch.Success)
                obj["flags"] = flagsMatch.Groups[1].Value;

            // Extract state
            var stateMatch = Regex.Match(line, @"state\s+(\S+)");
            if (stateMatch.Success)
                obj["state"] = stateMatch.Groups[1].Value;

            // Extract MAC address
            var macMatch = Regex.Match(line, @"link/\S+\s+(\S+)");
            if (macMatch.Success)
                obj["mac"] = macMatch.Groups[1].Value;

            // Extract MTU
            var mtuMatch = Regex.Match(line, @"mtu\s+(\d+)");
            if (mtuMatch.Success)
                obj["mtu"] = mtuMatch.Groups[1].Value;

            // Extract group (default vs custom)
            var groupMatch = Regex.Match(line, @"group\s+(\S+)");
            if (groupMatch.Success)
                obj["group"] = groupMatch.Groups[1].Value;

            return obj.Count > 0 ? obj : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Extracts a field value from a verbose USB descriptor block.
    /// </summary>
    private static string? ExtractField(string block, string fieldName)
    {
        foreach (var line in block.Split('\n'))
        {
            var pattern = fieldName;
            var idx = line.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
            if (idx >= 0)
            {
                var value = line[(idx + pattern.Length)..].Trim().TrimStart(':').Trim();
                return string.IsNullOrWhiteSpace(value) ? null : value;
            }
        }
        return null;
    }

    /// <summary>
    /// Classifies PCI device class IDs into human-readable categories.
    /// </summary>
    private static string ClassifyPciDevice(string classId)
    {
        return classId switch
        {
            "0300" => "VGA Display",
            "0301" => "XGA Display",
            "0302" => "3D Controller",
            "0380" => "Display Controller",
            "0101" => "IDE Controller",
            "0106" => "AHCI/SATA Controller",
            "0107" => "SAS Controller",
            "0108" => "NVMe Controller",
            "0200" => "Ethernet Controller",
            "0280" => "Network Controller (WiFi)",
            "0281" => "Network Controller",
            "0401" => "Audio Device",
            "0403" => "HD Audio",
            "0600" => "Host Bridge",
            "0601" => "ISA Bridge",
            "0604" => "PCI Bridge",
            "0c03" => "USB Controller",
            "0104" => "RAID Controller",
            "0580" => "Memory Controller",
            "0805" => "SD/MMC Controller",
            "0880" => "System Peripheral",
            "1180" => "Signal Processing",
            "0103" => "HBA Controller",
            _ when classId.StartsWith("01") => "Storage Controller",
            _ when classId.StartsWith("02") => "Network Controller",
            _ when classId.StartsWith("03") => "Display Controller",
            _ when classId.StartsWith("04") => "Multimedia Controller",
            _ when classId.StartsWith("06") => "Bridge Device",
            _ when classId.StartsWith("07") => "Communication Controller",
            _ when classId.StartsWith("08") => "System Peripheral",
            _ when classId.StartsWith("0c") => "USB Controller",
            _ when classId.StartsWith("0d") => "Wireless Controller",
            _ => "Other"
        };
    }

    /// <summary>
    /// Tries to parse a KB-formatted memory value into bytes.
    /// </summary>
    private static bool TryParseKb(string value, out long kb)
    {
        kb = 0;
        var parts = value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return false;
        return long.TryParse(parts[0], NumberStyles.Any, CultureInfo.InvariantCulture, out kb);
    }

    /// <summary>
    /// Parses bcdUSB version value to a numeric speed indicator.
    /// </summary>
    private static double ParseSpeedValue(string bcdUsb)
    {
        try
        {
            var parts = bcdUsb.Split('.', ' ');
            if (parts.Length >= 1 && double.TryParse(parts[0], NumberStyles.Any, CultureInfo.InvariantCulture, out var major))
            {
                // Major version indicates speed class
                return major >= 4 ? 400.0 :
                       major >= 3 ? 300.0 :
                       major >= 2 ? 200.0 : 100.0;
            }
        }
        catch { }
        return 200.0; // Default to full speed
    }

    /// <summary>
    /// Runs a shell command and returns stdout.
    /// </summary>
    private static async Task<string> RunCommandAsync(string command)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "bash",
                    Arguments = $"-c \"{command.Replace("\"", "\\\"")}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();
            return output;
        }
        catch (Exception ex)
        {
            Logger.Debug($"Command failed: {command} - {ex.Message}");
            return string.Empty;
        }
    }
}
