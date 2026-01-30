using Microsoft.Win32;
using System.Management;
using System.Text;
using System.Security.Cryptography;

namespace ImageWare.Shared;

public static class HardwareCode
{
    public static string Get(int length = 24)
    {
        if (length != 24)
            throw new ArgumentOutOfRangeException(nameof(length), "Use 24 chars.");

        var guid = ReadMachineGuid() ?? "no-guid";
        var cpu = ReadWmi("SELECT ProcessorId FROM Win32_Processor", "ProcessorId") ?? "no-cpu";
        var board = ReadWmi("SELECT SerialNumber FROM Win32_BaseBoard", "SerialNumber") ?? "no-board";

        var installSecret = GetOrCreateInstallSecret();

        var raw = $"v1|{guid}|{cpu}|{board}|{Convert.ToHexString(installSecret)}"
            .Trim()
            .ToLowerInvariant();

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        var b64url = CryptoUtil.Base64UrlEncode(hash);
        return b64url.Substring(0, length);
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
            "1mageWare"
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

            var secret = RandomNumberGenerator.GetBytes(32);
            var protOut = ProtectedData.Protect(secret, null, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(path, protOut);
            return secret;
        }
        catch
        {
            // fallback: still return something so app can run
            return RandomNumberGenerator.GetBytes(32);
        }
    }
}
