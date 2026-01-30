# 1mageware - Enhanced Theoretically Uncrackable Software

This is an enhanced version of the licensing system with multiple layers of advanced security features designed to make the software incredibly resistant to cracking attempts.

## Enhanced Security Features

### 1. Enhanced Hardware Fingerprinting
- Increased entropy from 24 to 32 characters for stronger uniqueness
- Added multiple hardware identifiers (BIOS, Video Controller, Disk Serial, etc.)
- Implemented anti-virtualization detection to prevent use in VMs
- Added anti-debugging checks to detect reverse engineering attempts

### 2. Advanced Cryptographic Protection
- AES encryption for locally stored license files
- Hardware-derived encryption keys that tie licenses to specific machines
- Enhanced signature verification with constant-time comparison
- Secure key derivation from multiple hardware sources

### 3. Runtime Anti-Tampering Mechanisms
- Detection of common reverse engineering tools (debuggers, decompilers)
- Periodic integrity checks during application execution
- Tamper detection algorithms that monitor for modifications
- Environmental validation throughout runtime

### 4. License Enforcement Features
- Run count limiting to prevent unlimited usage
- Enhanced file integrity verification covering more file types
- Secure storage in hidden application data directories
- Protection against common attack vectors

### 5. Obfuscation and Evasion Techniques
- Non-obvious file names and directory structures
- Encrypted license storage to prevent easy modification
- Runtime checks that make debugging more difficult
- Multiple fallback mechanisms for resilience

## Components

- **Client**: The protected application that validates licenses
- **LicenseGen**: The license generation tool for developers
- **Shared**: Shared libraries containing security functionality

## Usage

### For Developers:
1. Build the LicenseGen project to create licenses
2. Run the LicenseGen tool to generate signed licenses
3. Distribute the Client application with the embedded public key

### For License Generation:
1. Run the LicenseGen application
2. Enter the required information (hardware code, expiration, features)
3. Save the generated license file to the appropriate location

### For End Users:
1. The system will automatically validate the license upon startup
2. All security checks happen transparently
3. The application will only run if all validations pass

## Security Architecture

The enhanced system implements defense-in-depth principles with multiple layers:
- **Cryptographic Layer**: ECDSA signatures and AES encryption
- **Hardware Layer**: Comprehensive system fingerprinting
- **Runtime Layer**: Active monitoring and validation
- **Storage Layer**: Encrypted and obfuscated license storage
- **Environmental Layer**: Detection of virtualized/analytical environments

## Resistance to Common Attack Vectors

✅ **Key Extraction**: Keys are derived from hardware and encrypted
✅ **License Modification**: Protected by digital signatures and integrity checks
✅ **HWID Spoofing**: Multiple hardware identifiers make spoofing harder
✅ **VM/Emulation**: Active detection prevents virtualized environments
✅ **Debugging**: Anti-debugging checks terminate upon detection
✅ **Reverse Engineering**: Multiple obfuscation techniques employed
✅ **File Tampering**: Comprehensive integrity verification
✅ **Unlimited Usage**: Run count limiting prevents abuse

This enhanced version significantly increases the difficulty of cracking your software while maintaining usability for legitimate users. The layered approach ensures that bypassing one protection mechanism still leaves others intact.