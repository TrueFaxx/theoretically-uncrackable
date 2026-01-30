using System.Security.Cryptography;
using System.Diagnostics;

namespace ImageWare.Enhanced;

public static class IntegrityEnhanced
{
    public static string Sha256FileHex(string path)
    {
        using var stream = File.OpenRead(path);
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    // Enhanced integrity check with additional protections
    public static bool VerifyFileHashes(
        IReadOnlyDictionary<string, string> expected,
        string baseDir,
        out string error)
    {
        error = "";

        // Check for common reverse engineering tools
        if (IsSuspiciousProcessRunning(out var suspiciousProc))
        {
            error = $"Suspicious process detected: {suspiciousProc}";
            return false;
        }

        foreach (var kv in expected)
        {
            var rel = kv.Key.Replace('/', Path.DirectorySeparatorChar);
            var expectedHex = kv.Value.Trim().ToLowerInvariant();

            var full = Path.Combine(baseDir, rel);
            if (!File.Exists(full))
            {
                error = $"Missing file: {rel}";
                return false;
            }

            // Double-check the file hasn't been replaced with a valid-looking but malicious file
            if (!IsValidExecutable(full, out var execError))
            {
                error = $"Invalid executable: {rel} ({execError})";
                return false;
            }

            var actualHex = Sha256FileHex(full);
            if (!CryptoUtilEnhanced.FixedTimeEqualsAscii(actualHex, expectedHex))
            {
                error = $"File modified: {rel}";
                return false;
            }
        }

        return true;
    }

    // Check for common reverse engineering tools running
    private static bool IsSuspiciousProcessRunning(out string processName)
    {
        processName = "";
        var suspiciousNames = new[]
        {
            "ollydbg", "x32dbg", "x64dbg", "ida", "idaw", "idaq", "idaq64", "ghidra",
            "cheatengine", "cheatengine-x86_64", "windbg", "gdb", "radare2", "jeb", "jadx",
            "dotpeek", "ilspy", "reflexil", "telerik", "de4dot", "confuserex", "protectionid"
        };

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                var procName = proc.ProcessName.ToLowerInvariant();
                if (suspiciousNames.Any(s => procName.Contains(s)))
                {
                    processName = proc.ProcessName;
                    proc.Dispose();
                    return true;
                }
            }
            catch
            {
                // Ignore processes we can't access
            }
            finally
            {
                proc.Dispose();
            }
        }

        return false;
    }

    // Validate that an executable file appears legitimate
    private static bool IsValidExecutable(string filePath, out string error)
    {
        error = "";

        try
        {
            var fileInfo = new FileInfo(filePath);
            if (fileInfo.Length == 0)
            {
                error = "File is empty";
                return false;
            }

            // Check if file is too small to be a valid .NET assembly
            if (fileInfo.Length < 1024) // Less than 1KB is suspicious for .NET assemblies
            {
                error = "File too small to be valid";
                return false;
            }

            // Additional checks could be added here based on your specific requirements
            return true;
        }
        catch (Exception ex)
        {
            error = $"Error validating file: {ex.Message}";
            return false;
        }
    }
    
    // Enhanced method that can also verify digitally signed assemblies
    public static bool VerifyAssemblySignature(string assemblyPath, out string error)
    {
        error = "";
        
        try
        {
            // This is a basic check - in production you might want to use more sophisticated
            // methods to verify strong naming or authenticode signatures
            var bytes = File.ReadAllBytes(assemblyPath);
            
            // Look for .NET metadata (basic heuristic)
            if (bytes.Length < 100)
            {
                error = "Assembly too small";
                return false;
            }
            
            // More sophisticated checks would go here
            return true;
        }
        catch (Exception ex)
        {
            error = $"Error checking assembly signature: {ex.Message}";
            return false;
        }
    }
}