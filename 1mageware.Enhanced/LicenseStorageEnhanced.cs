using System.Text.Json;

namespace ImageWare.Enhanced;

public static class LicenseStorageEnhanced
{
    private static readonly object _lock = new object();
    
    public static string GetAppDir()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "1mageWare",
            "secure_data"
        );
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static string GetLicensePath()
        => Path.Combine(GetAppDir(), "license.dat"); // Changed extension to be less obvious

    public static string? TryReadLicense()
    {
        var path = GetLicensePath();
        if (!File.Exists(path)) 
            return null;
            
        try
        {
            var encryptedData = File.ReadAllBytes(path);
            var key = DeriveKeyFromHardware(); // Key derived from hardware to add another layer
            var decrypted = CryptoUtilEnhanced.DecryptWithKey(encryptedData, key);
            return Encoding.UTF8.GetString(decrypted);
        }
        catch
        {
            // If decryption fails, license might be corrupted or tampered
            return null;
        }
    }

    public static void SaveLicense(string licenseJson)
    {
        var path = GetLicensePath();
        var key = DeriveKeyFromHardware();
        var data = Encoding.UTF8.GetBytes(licenseJson);
        var encrypted = CryptoUtilEnhanced.EncryptWithKey(data, key);
        File.WriteAllBytes(path, encrypted);
    }
    
    // Track run counts for license enforcement
    public static int IncrementRunCount(string licenseId)
    {
        lock (_lock)
        {
            var runCountsPath = Path.Combine(GetAppDir(), "run_counts.json");
            Dictionary<string, int> runCounts = new Dictionary<string, int>();
            
            if (File.Exists(runCountsPath))
            {
                try
                {
                    var json = File.ReadAllText(runCountsPath);
                    runCounts = JsonSerializer.Deserialize<Dictionary<string, int>>(json) ?? new Dictionary<string, int>();
                }
                catch
                {
                    runCounts = new Dictionary<string, int>();
                }
            }
            
            if (runCounts.ContainsKey(licenseId))
                runCounts[licenseId]++;
            else
                runCounts[licenseId] = 1;
                
            var updatedJson = JsonSerializer.Serialize(runCounts, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(runCountsPath, updatedJson);
            
            return runCounts[licenseId];
        }
    }
    
    // Method to clear run count (for license renewal)
    public static void ClearRunCount(string licenseId)
    {
        lock (_lock)
        {
            var runCountsPath = Path.Combine(GetAppDir(), "run_counts.json");
            Dictionary<string, int> runCounts = new Dictionary<string, int>();
            
            if (File.Exists(runCountsPath))
            {
                try
                {
                    var json = File.ReadAllText(runCountsPath);
                    runCounts = JsonSerializer.Deserialize<Dictionary<string, int>>(json) ?? new Dictionary<string, int>();
                }
                catch
                {
                    runCounts = new Dictionary<string, int>();
                }
            }
            
            if (runCounts.ContainsKey(licenseId))
            {
                runCounts.Remove(licenseId);
                var updatedJson = JsonSerializer.Serialize(runCounts, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(runCountsPath, updatedJson);
            }
        }
    }
    
    // Derive encryption key from hardware characteristics to tie license to machine
    private static byte[] DeriveKeyFromHardware()
    {
        try
        {
            var hwCode = HardwareCodeEnhanced.Get(32); // Get hardware code
            var machineGuid = GetMachineGuid();
            var combined = $"{hwCode}|{machineGuid}|1mageWare";
            
            using var sha = SHA256.Create();
            return sha.ComputeHash(Encoding.UTF8.GetBytes(combined));
        }
        catch
        {
            // Fallback to a fixed key if hardware access fails
            return Encoding.UTF8.GetBytes("1mageWareDefaultKey2025!");
        }
    }
    
    private static string GetMachineGuid()
    {
        try
        {
            using var key = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64)
                .OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
            return key?.GetValue("MachineGuid")?.ToString() ?? "fallback_guid";
        }
        catch
        {
            return "fallback_guid";
        }
    }
}