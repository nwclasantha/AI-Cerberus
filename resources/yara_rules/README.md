# YARA Rules Collection

This directory contains YARA rules for malware detection used by the Malware Analysis Platform.

---

## 📁 Rule Files

### malware_indicators.yar
**Generic malware detection patterns**
- `Malware_Indicators`: Generic malicious behavior (injection, persistence, anti-analysis)
- `Process_Injection`: Memory injection techniques
- `Anti_Analysis`: Anti-debugging and anti-VM techniques
- `Persistence_Mechanism`: Registry and startup persistence
- `Network_Activity`: Suspicious network behavior

### trojans.yar
**Trojan detection rules**
- `Trojan_Generic`: Generic trojan indicators
- `RAT_Indicators`: Remote Access Trojan (RAT) behavior
- `Downloader_Trojan`: File download and execution
- `Backdoor_Indicators`: Backdoor functionality

### ransomware.yar
**Ransomware detection patterns**
- `Ransomware_Indicators`: Generic ransomware behavior
- `Crypto_Locker`: File encryption with shadow copy deletion
- `File_Encryptor`: File encryption functionality
- `Ransom_Note`: Ransom note text patterns

### infostealers.yar
**Information stealer detection**
- `Keylogger_Indicators`: Keylogging functionality
- `Password_Stealer`: Credential theft
- `Browser_Data_Theft`: Browser data exfiltration
- `Clipboard_Stealer`: Clipboard monitoring
- `Form_Grabber`: Form data interception
- `Screen_Capture`: Screenshot capabilities

### packers.yar
**Packer and obfuscator detection**
- `Packer_UPX`: UPX packer
- `Packer_Generic`: Generic packing indicators
- `Runtime_Unpacker`: Runtime unpacking behavior
- `Themida_Packer`: Themida/WinLicense
- `VMProtect_Packer`: VMProtect
- `ASPack_Packer`: ASPack
- `PECompact_Packer`: PECompact
- `MPRESS_Packer`: MPRESS
- `High_Entropy_Section`: High entropy detection
- `Dotnet_Obfuscator`: .NET obfuscation

---

## 🔍 Usage

### In the Application

The application automatically loads all YARA rules from this directory. Rules are compiled and used during analysis.

### Command Line

```bash
# Scan a file with specific rules
yara malware_indicators.yar suspicious_file.exe

# Scan with all rules
yara -r ./ suspicious_file.exe

# Get detailed match information
yara -s malware_indicators.yar suspicious_file.exe
```

### Python API

```python
from src.core import YaraEngine

# Use built-in rules
yara = YaraEngine()
matches = yara.analyze(file_path)

# Load custom rules
yara.load_rules_file("custom_rules.yar")
matches = yara.analyze(file_path)
```

---

## ✏️ Creating Custom Rules

### Basic Rule Structure

```yara
rule MyCustomRule {
    meta:
        description = "Description of what this rule detects"
        author = "Your Name"
        date = "2025-01-15"
        severity = "high"  // low, medium, high, critical
        category = "malware"  // malware, trojan, ransomware, etc.

    strings:
        $string1 = "suspicious_string" nocase
        $string2 = { 4D 5A 90 00 }  // Hex bytes
        $regex1 = /[a-z0-9]{32}/ ascii  // Regex pattern

    condition:
        any of them
}
```

### String Modifiers

```yara
strings:
    $a = "text" ascii          // ASCII strings
    $b = "text" wide           // Unicode strings
    $c = "text" nocase         // Case insensitive
    $d = "text" fullword       // Word boundaries
    $e = { 4D 5A [4-8] 90 }   // Hex with wildcards
    $f = /regex.*pattern/      // Regular expressions
```

### Condition Examples

```yara
condition:
    any of them                // At least one string matches
    all of them                // All strings match
    2 of them                  // At least 2 strings match
    $a and $b                  // Both strings match
    $a or $b                   // Either string matches
    #a > 5                     // String appears more than 5 times
    filesize < 100KB           // File size check
    uint16(0) == 0x5A4D        // MZ header check
```

---

## 📊 Severity Levels

- **Low**: Common, not necessarily malicious (e.g., UPX packer)
- **Medium**: Suspicious behavior (e.g., anti-debugging)
- **High**: Likely malicious (e.g., process injection)
- **Critical**: Definitely malicious (e.g., ransomware, RAT)

---

## 🎯 Best Practices

### Writing Effective Rules

1. **Be Specific**: Include multiple conditions to reduce false positives
2. **Use Metadata**: Always include description, severity, and category
3. **Test Thoroughly**: Test on both malicious and legitimate files
4. **Document**: Explain what the rule detects and why

### Performance Considerations

1. **Avoid Greedy Regex**: Use specific patterns instead of `.*`
2. **Limit String Searches**: Use `fullword` modifier when possible
3. **Combine Conditions**: Use logical operators efficiently
4. **Test Performance**: Large rule sets can slow analysis

### False Positive Reduction

1. **Multiple Indicators**: Require 2+ suspicious patterns
2. **Context Matters**: Combine API calls with behavior
3. **Legitimate Use Cases**: Consider normal software patterns
4. **File Type Checks**: Verify appropriate file format

---

## 🔄 Updating Rules

### Adding New Rules

1. Create a new `.yar` file or edit existing ones
2. Follow the naming convention: `category_name.yar`
3. Test rules independently before deploying
4. Restart application to load new rules

### Testing Rules

```bash
# Test rule syntax
yara --no-warnings rule_file.yar

# Test on sample files
yara rule_file.yar test_samples/

# Check for false positives
yara rule_file.yar clean_files/
```

---

## 📚 Rule Writing Resources

### YARA Documentation
- Official docs: https://yara.readthedocs.io/
- Rule writing guide: https://yara.readthedocs.io/en/stable/writingrules.html

### Sample Rule Repositories
- YARA-Rules: https://github.com/Yara-Rules/rules
- Awesome YARA: https://github.com/InQuest/awesome-yara

### Malware Analysis Resources
- MITRE ATT&CK: https://attack.mitre.org/
- MalAPI: https://malapi.io/
- Malware Bazaar: https://bazaar.abuse.ch/

---

## ⚠️ Important Notes

### Legal Considerations
- **Educational Purpose**: These rules are for authorized security research only
- **Permission Required**: Only scan files you have permission to analyze
- **Compliance**: Follow local laws and regulations

### Accuracy
- **Not Perfect**: YARA rules may have false positives/negatives
- **Context Matters**: Always combine with other analysis methods
- **Regular Updates**: Keep rules updated with new threats

### Performance
- **Large Files**: May take time to scan large files
- **Rule Complexity**: Complex rules slow down scanning
- **Testing**: Test rules on representative samples

---

## 🤝 Contributing Rules

If you create effective detection rules, consider contributing:

1. Test rules thoroughly
2. Document detection rationale
3. Include sample hashes (if available)
4. Submit via pull request

---

## 📝 Rule Template

Use this template for new rules:

```yara
/*
   Rule Name
   Brief description of what this detects
*/

rule Rule_Name {
    meta:
        description = "Detailed description"
        author = "Your Name"
        date = "YYYY-MM-DD"
        severity = "medium"  // low, medium, high, critical
        category = "malware"  // malware, trojan, ransomware, etc.
        reference = "https://..."  // Optional
        hash = "MD5/SHA256"  // Optional sample hash

    strings:
        // Define detection patterns
        $string1 = "pattern" nocase
        $string2 = { HEX BYTES }
        $regex1 = /regex.*pattern/

    condition:
        // Define match logic
        any of them
}
```

---

**Note**: Always test rules in safe environments before deploying to production.
