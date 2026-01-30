using Microsoft.Win32;
using System.Management;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace ImageWare.Shared;

public static class HardwareCode
{
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsDebuggerPresent();

    [DllImport("ntdll.dll")]
    private static extern uint RtlGetCurrentPeb();

    public static string Get(int length = 32) // Increased length for better entropy
    {
        if (length < 24)
            throw new ArgumentOutOfRangeException(nameof(length), "Use at least 24 chars.");

        var parts = new List<string>();
        
        // Traditional hardware identifiers
        var guid = ReadMachineGuid() ?? "no-guid";
        var cpu = ReadWmi("SELECT ProcessorId FROM Win32_Processor", "ProcessorId") ?? "no-cpu";
        var board = ReadWmi("SELECT SerialNumber FROM Win32_BaseBoard", "SerialNumber") ?? "no-board";
        var disk = ReadWmi("SELECT SerialNumber FROM Win32_DiskDrive WHERE Index=0", "SerialNumber") ?? "no-disk";
        
        // Additional hardware identifiers
        var bios = ReadWmi("SELECT SMBIOSBIOSVersion FROM Win32_BIOS", "SMBIOSBIOSVersion") ?? "no-bios";
        var video = ReadWmi("SELECT Name FROM Win32_VideoController", "Name") ?? "no-video";

        // Process-specific and runtime information
        var installSecret = GetOrCreateInstallSecret();
        var processId = Environment.ProcessId.ToString();
        var startupTime = Environment.TickCount64.ToString();

        // Runtime checks to detect tampering
        var isDebugged = IsDebuggerPresent() ? "debugged" : "clean";
        var processHandle = GetCurrentProcess().ToString();

        // Combine all identifiers
        var raw = $"v2|{guid}|{cpu}|{board}|{disk}|{bios}|{video}|{processId}|{startupTime}|{isDebugged}|{processHandle}|{Convert.ToHexString(installSecret)}"
            .Trim()
            .ToLowerInvariant();

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        var b64url = CryptoUtil.Base64UrlEncode(hash);
        return b64url.Substring(0, Math.Min(length, b64url.Length));
    }

    private static string? ReadMachineGuid()
    {
        try
        {
            using var key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                .OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
            return key?.GetValue("MachineGuid")?.ToString();
        }
        catch { return null; }
    }

    private static string? ReadWmi(string query, string property)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(query);
            foreach (var obj in searcher.Get())
            {
                var v = obj[property]?.ToString();
                if (!string.IsNullOrWhiteSpace(v)) return v.Trim();
            }
        }
        catch { }
        return null;
    }

    private static byte[] GetOrCreateInstallSecret()
    {
        var installDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "1mageWare", 
            "secure"
        );
        Directory.CreateDirectory(installDir);

        var path = Path.Combine(installDir, "install_secret.bin");

        try
        {
            if (File.Exists(path))
            {
                var protBytes = File.ReadAllBytes(path);
                return ProtectedData.Unprotect(protBytes, null, DataProtectionScope.CurrentUser);
            }

            var secret = RandomNumberGenerator.GetBytes(64); // Increased entropy
            var protOut = ProtectedData.Protect(secret, null, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(path, protOut);
            return secret;
        }
        catch
        {
            // Fallback with random generation if DPAPI fails
            return RandomNumberGenerator.GetBytes(64);
        }
    }
    
    // Anti-virtualization detection
    public static bool IsVirtualEnvironment()
    {
        try
        {
            var wmiQuery = "SELECT * FROM Win32_ComputerSystem";
            using var searcher = new ManagementObjectSearcher(wmiQuery);
            foreach (ManagementObject obj in searcher.Get())
            {
                var manufacturer = obj["Manufacturer"]?.ToString();
                var model = obj["Model"]?.ToString();

                if (!string.IsNullOrEmpty(manufacturer))
                {
                    if (manufacturer.Contains("VMware", StringComparison.OrdinalIgnoreCase) ||
                        manufacturer.Contains("VirtualBox", StringComparison.OrdinalIgnoreCase) ||
                        manufacturer.Contains("Xen", StringComparison.OrdinalIgnoreCase) ||
                        manufacturer.Contains("QEMU", StringComparison.OrdinalIgnoreCase) ||
                        manufacturer.Contains("Microsoft Corporation", StringComparison.OrdinalIgnoreCase) && 
                        !string.IsNullOrEmpty(model) && 
                        model.Contains("Virtual", StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }
        }
        catch { }

        // Check for common virtualization artifacts
        var virtualProcesses = new[] { "vboxservice.exe", "vmtoolsd.exe", "vmsrvc.exe", "prl_cc.exe", "prl_tools.exe" };
        foreach (var proc in virtualProcesses)
        {
            if (System.Diagnostics.Process.GetProcessesByName(Path.GetFileNameWithoutExtension(proc)).Length > 0)
                return true;
        }

        return false;
    }
    
    // Check for debugger presence
    public static bool IsDebugged()
    {
        return IsDebuggerPresent() || System.Diagnostics.Debugger.IsAttached;
    }
}
