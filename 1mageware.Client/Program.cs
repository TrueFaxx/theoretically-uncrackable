// Enhanced public key (this would be generated during key generation)
const string PublicKeySpkiB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGKpvGydWaygAvJ3qW+03oGLNv11y+rjFzP+8A6j6VcL9pA8+f68WcA53j/JYMFvP5zhvk4hGct+nyOgMlnaynw==";

try
{
    // Enhanced hardware fingerprinting
    var hw = HardwareCode.Get(32); // Increased to 32 chars for more entropy

    // Check for virtual environment before proceeding
    if (HardwareCode.IsVirtualEnvironment())
    {
        Console.WriteLine("Virtual environment detected. Access denied.");
        Environment.Exit(1);
    }

    // Check for debugger
    if (HardwareCode.IsDebugged())
    {
        Console.WriteLine("Debugger detected. Access denied.");
        Environment.Exit(1);
    }

    var licenseJson = LicenseStorage.TryReadLicense();
    if (licenseJson is null)
    {
        Console.WriteLine("No license found.");
        Console.WriteLine("Hardware Code (send to dev): " + hw);
        Environment.Exit(1);
    }

    if (!LicenseSigner.TryValidateLicense(PublicKeySpkiB64, licenseJson, hw, out var payload, out var err))
    {
        Console.WriteLine("License invalid: " + err);
        Console.WriteLine("Hardware Code: " + hw);
        Environment.Exit(1);
    }

    // Enhanced integrity checks if enabled in license
    if (payload!.EnableIntegrity && payload!.FileHashes is { Count: > 0 })
    {
        var baseDir = AppContext.BaseDirectory; // folder where exe lives
        
        // Perform enhanced integrity check
        if (!Integrity.VerifyFileHashes(payload.FileHashes, baseDir, out var iErr))
        {
            Console.WriteLine("Integrity fail: " + iErr);
            Environment.Exit(1);
        }
        
        // Additional check for reverse engineering tools
        if (Integrity.IsSuspiciousProcessRunning(out var susProc))
        {
            Console.WriteLine($"Suspicious process detected: {susProc}");
            Environment.Exit(1);
        }
    }

    Console.WriteLine("License OK: " + payload.LicenseId);
    Console.WriteLine("Expires: " + payload.ExpiresUtc.ToUniversalTime().ToString("u"));
    Console.WriteLine("Features: " + string.Join(", ", payload.Features));
    Console.WriteLine("Run Count: " + payload.CurrentRunCount);

    // Enhanced protection: Tamper detection
    if (!IsTamperDetected())
    {
        // All checks passed - run protected application
        Console.WriteLine("Running app securely...");
        
        // Your protected application code goes here
        RunProtectedApplication();
    }
    else
    {
        Console.WriteLine("Tamper detected! Terminating.");
        Environment.Exit(1);
    }
}
catch (Exception ex)
{
    Console.WriteLine($"Unexpected error: {ex.Message}");
    Environment.Exit(1);
}

static bool IsTamperDetected()
{
    // Additional runtime checks for tampering
    try
    {
        // Check if the executing assembly has been modified
        var assemblyLocation = System.Reflection.Assembly.GetExecutingAssembly().Location;
        if (string.IsNullOrEmpty(assemblyLocation))
        {
            // Running from memory - potentially suspicious
            return true;
        }

        // Check for common .NET decompiler/analysis attributes that might indicate tampering
        var assembly = System.Reflection.Assembly.GetExecutingAssembly();
        var attrs = assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyMetadataAttribute), false);
        
        // If the assembly has been recompiled with different metadata, it might be tampered
        // This is a simplified check - more sophisticated checks would be needed in practice
        
        return false; // No tampering detected
    }
    catch
    {
        return true; // Error accessing assembly info - assume tampering
    }
}

static void RunProtectedApplication()
{
    // Placeholder for your actual application logic
    Console.WriteLine("Protected application is now running securely!");
    
    // Your actual application code would go here
    while (true)
    {
        // Main application loop with periodic security checks
        System.Threading.Thread.Sleep(1000); // Simulate work
        
        // Periodic security check
        if (HardwareCode.IsDebugged() || HardwareCode.IsVirtualEnvironment())
        {
            Console.WriteLine("Security violation detected during execution!");
            Environment.Exit(1);
        }
    }
}