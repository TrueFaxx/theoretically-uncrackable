# 1mageware Enhanced Security Module

This enhanced security module contains advanced protection features to make your software incredibly resistant to cracking attempts.

## Features

- Enhanced hardware fingerprinting with 32-character identifiers
- Anti-virtualization and anti-debugging detection
- Encrypted license storage with hardware-derived keys
- Advanced integrity verification
- Run count limiting
- Detection of reverse engineering tools

## Integration

To use the enhanced security features, reference the classes in this module in place of the standard ones:

- Use `HardwareCodeEnhanced.Get()` instead of `HardwareCode.Get()`
- Use `LicenseSignerEnhanced` instead of `LicenseSigner`
- Use `LicenseStorageEnhanced` instead of `LicenseStorage`
- Use `IntegrityEnhanced` instead of `Integrity`

## Security Strength

The enhanced module implements multiple layers of protection:
1. Cryptographic security with ECDSA signatures
2. Hardware binding with comprehensive system fingerprinting
3. Runtime monitoring and validation
4. Secure storage with obfuscation
5. Environmental awareness (VM, debugger detection)

## Usage

See `ClientEnhanced.cs` for a complete example of how to integrate all security features.