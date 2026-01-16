# AI-Cerberus

## The Three-Headed Guardian Against Malicious Code

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.10+-green)
![License](https://img.shields.io/badge/license-MIT-purple)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)

---

**AI-Cerberus** is an enterprise-grade malware analysis platform featuring multi-layered threat detection powered by artificial intelligence. Like the mythological three-headed guardian dog, it employs three independent detection engines to ensure no threat escapes.

<img width="1345" height="692" alt="image" src="https://github.com/user-attachments/assets/3f29fc0c-ee99-438c-bebc-feb4a6961115" />

---

## Table of Contents

1. [Features](#features)
2. [Architecture Overview](#architecture-overview)
3. [System Architecture](#system-architecture)
4. [Component Details](#component-details)
5. [Installation](#installation)
6. [Quick Start](#quick-start)
7. [Usage Guide](#usage-guide)
8. [Configuration](#configuration)
9. [API Reference](#api-reference)
10. [Development](#development)
11. [Troubleshooting](#troubleshooting)
12. [Contributing](#contributing)
13. [License](#license)

---

## Features

<img width="1386" height="682" alt="image" src="https://github.com/user-attachments/assets/0f9e3d78-101a-47d0-bcb6-379978c67042" />

### Three Detection Heads

| Head | Engine | Color | Description |
|------|--------|-------|-------------|
| **ML** | Machine Learning | Blue | Neural networks & ensemble classifiers (RF, GB, NN) |
| **YARA** | Signature Scanning | Green | Pattern-based malware family detection |
| **BEH** | Behavioral Analysis | Orange | Runtime behavior profiling & API analysis |

### Core Capabilities

<img width="1356" height="691" alt="image" src="https://github.com/user-attachments/assets/2a388118-c961-4512-924b-861cffd7acd2" />

- **Multi-Format Binary Analysis** - PE, ELF, Mach-O support
- **Advanced Disassembly** - x86, x64, ARM with suspicious code highlighting
- **100+ ML Features** - Comprehensive feature extraction for classification
- **YARA Rule Engine** - Custom rules + malware family signatures
- **Behavioral Profiling** - 20+ behavior categories detected
- **VirusTotal Integration** - Automatic hash lookup & detection ratios
- **Automated Threat Scoring** - 0-100 scale with detailed breakdown
- **Batch Processing** - Analyze multiple files sequentially
- **Plugin Architecture** - Extend with custom analyzers
- **Dark Theme UI** - Professional PyQt6 interface

### Detection Categories

```
┌─────────────────────────────────────────────────────────────────────┐
│  BEHAVIORAL DETECTION CAPABILITIES                                  │
├─────────────────────────────────────────────────────────────────────┤
│  ✓ Process Injection      ✓ Persistence Mechanisms                 │
│  ✓ Anti-Debugging         ✓ Anti-VM Detection                      │
│  ✓ Network Operations     ✓ Cryptographic Activity                 │
│  ✓ Keylogging             ✓ Screen Capture                         │
│  ✓ Privilege Escalation   ✓ Registry Manipulation                  │
│  ✓ File Operations        ✓ Service Installation                   │
│  ✓ Backdoor Detection     ✓ C2 Communication                       │
│  ✓ Code Injection         ✓ DLL Hijacking                          │
│  ✓ Rootkit Indicators     ✓ Data Exfiltration                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Architecture Overview

<img width="1371" height="646" alt="image" src="https://github.com/user-attachments/assets/4dbac0de-c5c9-4326-b08a-a2af917d4998" />

### High-Level Architecture

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                            AI-CERBERUS ARCHITECTURE                           ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
║  │                         PRESENTATION LAYER                               │ ║
║  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   │ ║
║  │  │   PyQt6      │ │   Views      │ │  Components  │ │    Theme     │   │ ║
║  │  │   App        │ │  (11 views)  │ │  (Sidebar,   │ │   (Dark)     │   │ ║
║  │  │              │ │              │ │   Toolbar)   │ │              │   │ ║
║  │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘   │ ║
║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                      │                                       ║
║                                      ▼                                       ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
║  │                         CONTROLLER LAYER                                 │ ║
║  │  ┌─────────────────────────────────────────────────────────────────┐   │ ║
║  │  │                      MainWindow                                  │   │ ║
║  │  │   • Analysis orchestration    • Threat scoring                  │   │ ║
║  │  │   • Background threading      • Signal/slot coordination        │   │ ║
║  │  │   • Batch processing          • Drag-and-drop handling          │   │ ║
║  │  └─────────────────────────────────────────────────────────────────┘   │ ║
║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                      │                                       ║
║                                      ▼                                       ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
║  │                    THREE-HEADED DETECTION ENGINE                         │ ║
║  │                                                                          │ ║
║  │   ┌────────────────┐  ┌────────────────┐  ┌────────────────┐           │ ║
║  │   │    HEAD 1      │  │    HEAD 2      │  │    HEAD 3      │           │ ║
║  │   │  ML DETECTION  │  │ YARA SCANNING  │  │  BEHAVIORAL    │           │ ║
║  │   │                │  │                │  │                │           │ ║
║  │   │ • RandomForest │  │ • Signatures   │  │ • API Analysis │           │ ║
║  │   │ • GradBoost    │  │ • Packers      │  │ • Indicators   │           │ ║
║  │   │ • Neural Net   │  │ • Families     │  │ • Risk Score   │           │ ║
║  │   │ • 100+ features│  │ • Custom rules │  │ • 20+ patterns │           │ ║
║  │   │                │  │                │  │                │           │ ║
║  │   │    [BLUE]      │  │    [GREEN]     │  │   [ORANGE]     │           │ ║
║  │   └────────────────┘  └────────────────┘  └────────────────┘           │ ║
║  │                                                                          │ ║
║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                      │                                       ║
║                                      ▼                                       ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
║  │                         CORE ANALYSIS LAYER                              │ ║
║  │                                                                          │ ║
║  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐     │ ║
║  │  │  Hash    │ │ Entropy  │ │  String  │ │    PE    │ │  Disasm  │     │ ║
║  │  │ Calc    │ │ Analyzer │ │ Extractor│ │ Analyzer │ │  Engine  │     │ ║
║  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘     │ ║
║  │                                                                          │ ║
║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                      │                                       ║
║                                      ▼                                       ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
║  │                         DATA LAYER                                       │ ║
║  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐      │ ║
║  │  │    SQLAlchemy    │  │   Config YAML    │  │   File System    │      │ ║
║  │  │    (SQLite)      │  │                  │  │                  │      │ ║
║  │  └──────────────────┘  └──────────────────┘  └──────────────────┘      │ ║
║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                      │                                       ║
║                                      ▼                                       ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
║  │                       INTEGRATION LAYER                                  │ ║
║  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   │ ║
║  │  │  VirusTotal  │ │   Hybrid     │ │   Custom     │ │   Plugins    │   │ ║
║  │  │     API      │ │  Analysis    │ │   Sandbox    │ │    SDK       │   │ ║
║  │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘   │ ║
║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## System Architecture

<img width="1390" height="672" alt="image" src="https://github.com/user-attachments/assets/1d0483c6-d583-4a3d-8f96-680538f53060" />

### Directory Structure

```
MalwareAnalyzer/
│
├── main.py                      # Application entry point
├── config.yaml                  # Global configuration
├── requirements.txt             # Python dependencies
├── create_icon_simple.py        # Icon generation script
│
├── resources/                   # Application resources
│   ├── icons/                   # UI icons
│   │   ├── cerberus.ico        # Main application icon
│   │   └── cerberus_hq.svg     # High-quality vector icon
│   ├── fonts/                   # Custom fonts
│   └── yara_rules/              # YARA signature rules
│       ├── malware/             # Generic malware signatures
│       ├── packers/             # Packer detection rules
│       └── suspicious/          # Suspicious behavior patterns
│
├── src/                         # Main source code
│   │
│   ├── core/                    # Analysis engines (10 modules)
│   │   ├── __init__.py
│   │   ├── base_analyzer.py     # Abstract base class
│   │   ├── hash_calculator.py   # MD5/SHA/SSDEEP/TLSH hashing
│   │   ├── entropy_analyzer.py  # Entropy & packing detection
│   │   ├── string_extractor.py  # String extraction & categorization
│   │   ├── pe_analyzer.py       # PE file parsing
│   │   ├── elf_analyzer.py      # ELF file parsing
│   │   ├── yara_engine.py       # YARA rule scanning
│   │   ├── behavior_analyzer.py # Behavioral analysis
│   │   ├── disassembler.py      # Capstone disassembly
│   │   └── analysis_modes.py    # Analysis mode presets
│   │
│   ├── ml/                      # Machine Learning (4 modules)
│   │   ├── __init__.py
│   │   ├── feature_extractor.py # 100+ feature extraction
│   │   ├── classifier.py        # Ensemble classifier (RF/GB/NN)
│   │   ├── neural_classifier.py # TensorFlow neural network
│   │   └── auto_trainer.py      # Automatic model training
│   │
│   ├── ui/                      # User Interface (PyQt6)
│   │   ├── __init__.py
│   │   ├── app.py               # Application initialization
│   │   ├── main_window.py       # Central UI controller
│   │   ├── theme/               # Theme system
│   │   │   ├── colors.py        # Color palette
│   │   │   ├── dark_theme.py    # Dark mode stylesheet
│   │   │   └── theme_manager.py # Theme switching
│   │   ├── components/          # Reusable UI components
│   │   │   ├── sidebar.py       # Navigation sidebar
│   │   │   ├── toolbar.py       # Main toolbar
│   │   │   ├── tab_manager.py   # Tab management
│   │   │   ├── status_bar.py    # Status information
│   │   │   ├── progress_overlay.py # Progress modal
│   │   │   ├── toast.py         # Notifications
│   │   │   └── charts/          # Visualization charts
│   │   │       ├── threat_gauge.py  # Threat score gauge
│   │   │       ├── entropy_chart.py # Entropy graph
│   │   │       └── pie_chart.py     # Statistics pie chart
│   │   └── views/               # Main view panels (11 views)
│   │       ├── dashboard_view.py    # Landing page
│   │       ├── analysis_view.py     # Analysis results
│   │       ├── hex_view.py          # Hex dump viewer
│   │       ├── disasm_view.py       # Disassembly viewer
│   │       ├── strings_view.py      # String listing
│   │       ├── yara_view.py         # YARA rule manager
│   │       ├── ml_view.py           # ML model management
│   │       ├── virustotal_view.py   # VirusTotal integration
│   │       ├── sandbox_view.py      # Sandbox integration
│   │       ├── history_view.py      # Analysis history
│   │       └── plugin_view.py       # Plugin manager
│   │
│   ├── database/                # Data persistence
│   │   ├── __init__.py
│   │   ├── models.py            # SQLAlchemy ORM schema
│   │   └── repository.py        # Data access layer
│   │
│   ├── integrations/            # Third-party services
│   │   ├── __init__.py
│   │   ├── virustotal.py        # VirusTotal API v3
│   │   ├── hybrid_analysis.py   # Hybrid Analysis sandbox
│   │   └── custom_sandbox.py    # Custom sandbox (SSH)
│   │
│   ├── plugins/                 # Plugin system
│   │   ├── __init__.py
│   │   ├── base_plugin.py       # Plugin interface
│   │   └── plugin_manager.py    # Plugin loader
│   │
│   └── utils/                   # Utilities
│       ├── __init__.py
│       ├── config.py            # Configuration management
│       ├── logger.py            # Structured logging
│       ├── exceptions.py        # Custom exceptions
│       └── helpers.py           # Utility functions
│
├── tests/                       # Test suite
│   ├── test_analyzers.py
│   ├── test_ml.py
│   └── test_ui.py
│
└── docs/                        # Documentation
    ├── API.md
    ├── PLUGINS.md
    └── CONTRIBUTING.md
```

---

## Component Details

### 1. Core Analysis Engines

#### Hash Calculator (`hash_calculator.py`)

```python
# Computed hashes for each sample:
┌────────────────────────────────────────────────┐
│  Hash Type    │  Purpose                       │
├────────────────────────────────────────────────┤
│  MD5          │  Legacy identification         │
│  SHA1         │  Legacy identification         │
│  SHA256       │  Primary identification        │
│  SHA512       │  Extended hash                 │
│  SSDEEP       │  Fuzzy hashing (similarity)    │
│  TLSH         │  Locality-sensitive hash       │
│  IMPHASH      │  Import table hash (PE)        │
└────────────────────────────────────────────────┘
```

#### PE Analyzer (`pe_analyzer.py`)

<img width="1363" height="683" alt="image" src="https://github.com/user-attachments/assets/ba7cce23-4670-4ff7-a364-4a1b78f0f29b" />

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PE FILE ANALYSIS                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐            │
│   │ DOS Header  │───▶│ PE Header   │───▶│  Optional   │            │
│   │             │    │             │    │   Header    │            │
│   └─────────────┘    └─────────────┘    └─────────────┘            │
│                                               │                      │
│         ┌─────────────────────────────────────┘                      │
│         ▼                                                            │
│   ┌───────────────────────────────────────────────────────────┐     │
│   │                    SECTIONS                                │     │
│   │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐           │     │
│   │  │.text │ │.data │ │.rdata│ │.rsrc │ │.reloc│  ...      │     │
│   │  │      │ │      │ │      │ │      │ │      │           │     │
│   │  │ CODE │ │ DATA │ │CONST │ │ RES  │ │RELOC │           │     │
│   │  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘           │     │
│   └───────────────────────────────────────────────────────────┘     │
│                                                                      │
│   ┌─────────────────────┐    ┌─────────────────────┐               │
│   │      IMPORTS        │    │      EXPORTS        │               │
│   │                     │    │                     │               │
│   │  kernel32.dll       │    │  DllMain            │               │
│   │   - CreateFile      │    │  ExportedFunc1      │               │
│   │   - WriteFile       │    │  ExportedFunc2      │               │
│   │  ws2_32.dll         │    │                     │               │
│   │   - socket          │    │                     │               │
│   │   - connect         │    │                     │               │
│   └─────────────────────┘    └─────────────────────┘               │
│                                                                      │
│   ANOMALY DETECTION:                                                 │
│   ✓ Executable + Writable sections                                  │
│   ✓ Unusual section names (.upx, .themida, .aspack)                │
│   ✓ Zero raw size / non-zero virtual size                          │
│   ✓ Entry point outside code section                                │
│   ✓ High entropy sections (packed/encrypted)                        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

#### Behavioral Analyzer (`behavior_analyzer.py`)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    BEHAVIORAL ANALYSIS ENGINE                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌───────────────────┐  ┌───────────────────┐  ┌───────────────┐   │
│  │ PROCESS INJECTION │  │ PERSISTENCE       │  │ NETWORK       │   │
│  │                   │  │                   │  │               │   │
│  │ WriteProcessMemory│  │ RegSetValue       │  │ WSAStartup    │   │
│  │ VirtualAllocEx    │  │ CreateService     │  │ socket        │   │
│  │ CreateRemoteThread│  │ SchTaskCreate     │  │ connect       │   │
│  │ NtUnmapView       │  │ Run/RunOnce keys  │  │ send/recv     │   │
│  └───────────────────┘  └───────────────────┘  └───────────────┘   │
│                                                                      │
│  ┌───────────────────┐  ┌───────────────────┐  ┌───────────────┐   │
│  │ ANTI-DEBUGGING    │  │ ANTI-VM           │  │ CRYPTOGRAPHY  │   │
│  │                   │  │                   │  │               │   │
│  │ IsDebuggerPresent │  │ VMware detection  │  │ CryptEncrypt  │   │
│  │ CheckRemoteDebug  │  │ VirtualBox detect │  │ CryptDecrypt  │   │
│  │ NtQueryInfoProcess│  │ Sandbox evasion   │  │ AES/RSA calls │   │
│  └───────────────────┘  └───────────────────┘  └───────────────┘   │
│                                                                      │
│  ┌───────────────────┐  ┌───────────────────┐  ┌───────────────┐   │
│  │ KEYLOGGING        │  │ SCREEN CAPTURE    │  │ BACKDOOR      │   │
│  │                   │  │                   │  │               │   │
│  │ GetAsyncKeyState  │  │ BitBlt            │  │ cmd.exe spawn │   │
│  │ SetWindowsHookEx  │  │ CreateCompatibleDC│  │ Shell reverse │   │
│  │ GetKeyboardState  │  │ GetDC/GetDCEx     │  │ Remote access │   │
│  └───────────────────┘  └───────────────────┘  └───────────────┘   │
│                                                                      │
│  RISK CALCULATION:                                                   │
│  • Each indicator weighted by severity                              │
│  • Combined score: 0-100                                            │
│  • Mapped to threat level: LOW/MEDIUM/HIGH/CRITICAL                 │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

#### Disassembler (`disassembler.py`)

<img width="1387" height="706" alt="image" src="https://github.com/user-attachments/assets/ab8b52bd-522f-4d4f-850a-5b14e357c8f2" />

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DISASSEMBLY ENGINE (Capstone)                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  SUPPORTED ARCHITECTURES:                                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
│  │   x86    │  │   x64    │  │   ARM    │  │  ARM64   │           │
│  │  32-bit  │  │  64-bit  │  │  32-bit  │  │  64-bit  │           │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘           │
│                                                                      │
│  DISASSEMBLY OUTPUT:                                                 │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │ ADDRESS     BYTES              MNEMONIC  OPERANDS              │ │
│  │ ──────────────────────────────────────────────────────────────│ │
│  │ 0x00401000  55                 push      rbp                   │ │
│  │ 0x00401001  48 89 e5           mov       rbp, rsp              │ │
│  │ 0x00401004  48 83 ec 20        sub       rsp, 0x20             │ │
│  │ 0x00401008  e8 00 10 00 00     call      CreateProcessA  [!]   │ │
│  │                                          ^^^^^^^^^^^^^^^^       │ │
│  │                                          SUSPICIOUS - RED BG    │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  SUSPICIOUS PATTERNS DETECTED:                                       │
│  • Dangerous API calls (CreateProcess, VirtualAlloc, etc.)          │
│  • Self-modifying code                                              │
│  • Direct syscalls (evasion)                                        │
│  • XOR encoding/decoding loops                                      │
│  • Anti-debugging instructions                                       │
│                                                                      │
│  VISUAL HIGHLIGHTING:                                                │
│  • CRITICAL - Red background                                        │
│  • HIGH - Orange background                                         │
│  • MEDIUM - Yellow background                                       │
│  • LOW - Light yellow background                                    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 2. Machine Learning Module

```
┌─────────────────────────────────────────────────────────────────────┐
│                    MACHINE LEARNING PIPELINE                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                 FEATURE EXTRACTION (100+ features)           │   │
│  │                                                               │   │
│  │  FILE METADATA          ENTROPY           PE HEADERS          │   │
│  │  • File size            • Overall         • Architecture      │   │
│  │  • Type detection       • Per-section     • Subsystem         │   │
│  │  • Timestamp            • Variance        • Entry point       │   │
│  │                         • Max/Min         • Image base        │   │
│  │                                                               │   │
│  │  SECTIONS               IMPORTS           STRINGS             │   │
│  │  • Count                • By category     • URLs count        │   │
│  │  • Entropy stats        • Networking      • IPs count         │   │
│  │  • Executable flags     • Crypto APIs     • Registry paths    │   │
│  │  • Writable flags       • Anti-debug      • Suspicious count  │   │
│  │                         • Injection       • Base64 count      │   │
│  │                                                               │   │
│  │  BYTE STATISTICS        RESOURCES         PACKER INDICATORS   │   │
│  │  • Mean value           • Count           • Section names     │   │
│  │  • Standard dev         • Entropy         • Entry point loc   │   │
│  │  • Null byte ratio      • Version info    • Overlay data      │   │
│  │  • High byte ratio      • Manifest        • Import count      │   │
│  │                                                               │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                   │                                  │
│                                   ▼                                  │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    ENSEMBLE CLASSIFIER                        │   │
│  │                                                               │   │
│  │      ┌───────────────┐                                       │   │
│  │      │ StandardScaler │  ← Feature Normalization             │   │
│  │      └───────────────┘                                       │   │
│  │              │                                                │   │
│  │    ┌─────────┼─────────┬─────────┐                          │   │
│  │    ▼         ▼         ▼         ▼                          │   │
│  │ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────────┐                    │   │
│  │ │Random│ │Grad  │ │Neural│ │Heuristic │                    │   │
│  │ │Forest│ │Boost │ │ Net  │ │(Fallback)│                    │   │
│  │ │      │ │      │ │      │ │          │                    │   │
│  │ │ 100  │ │ 100  │ │TFlow │ │ Rules    │                    │   │
│  │ │trees │ │ est. │ │Keras │ │ Based    │                    │   │
│  │ └──────┘ └──────┘ └──────┘ └──────────┘                    │   │
│  │    │         │         │                                    │   │
│  │    └─────────┴─────────┘                                    │   │
│  │              │                                                │   │
│  │              ▼                                                │   │
│  │      ┌───────────────┐                                       │   │
│  │      │ Voting Average │  ← Probability Averaging             │   │
│  │      └───────────────┘                                       │   │
│  │              │                                                │   │
│  │              ▼                                                │   │
│  │  ┌─────────────────────────────────────────────────────┐    │   │
│  │  │  OUTPUT: benign | suspicious | malicious            │    │   │
│  │  │          + confidence score (0.0 - 1.0)             │    │   │
│  │  └─────────────────────────────────────────────────────┘    │   │
│  │                                                               │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 3. Threat Scoring Algorithm

```
┌─────────────────────────────────────────────────────────────────────┐
│                    THREAT SCORE CALCULATION                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  SCORING COMPONENTS:                                                 │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                      │
│  ┌────────────────────┬───────────────────┬───────────────────────┐│
│  │ COMPONENT          │ MAX POINTS        │ CALCULATION           ││
│  ├────────────────────┼───────────────────┼───────────────────────┤│
│  │ YARA Matches       │ 25+ points        │ critical=25, high=15, ││
│  │                    │                   │ medium=8, low=3       ││
│  ├────────────────────┼───────────────────┼───────────────────────┤│
│  │ Behavioral         │ 70 points         │ behavior_score × 0.7  ││
│  │                    │                   │                       ││
│  ├────────────────────┼───────────────────┼───────────────────────┤│
│  │ Entropy            │ 15 points         │ packed=10, encrypted=15││
│  │                    │                   │                       ││
│  ├────────────────────┼───────────────────┼───────────────────────┤│
│  │ ML Classification  │ 20 points         │ malicious=20×conf     ││
│  │                    │                   │ suspicious=10×conf    ││
│  ├────────────────────┼───────────────────┼───────────────────────┤│
│  │ VirusTotal         │ 20 points         │ detections/total × 20 ││
│  │                    │                   │                       ││
│  ├────────────────────┼───────────────────┼───────────────────────┤│
│  │ Suspicious Strings │ 10 points         │ min(count, 10)        ││
│  │                    │                   │                       ││
│  ├────────────────────┼───────────────────┼───────────────────────┤│
│  │ PE Anomalies       │ 10 points         │ 2 points per anomaly  ││
│  │                    │                   │ (max 5 anomalies)     ││
│  └────────────────────┴───────────────────┴───────────────────────┘│
│                                                                      │
│  TOTAL POSSIBLE: 170+ points (capped at 100)                        │
│                                                                      │
│  CLASSIFICATION THRESHOLDS:                                          │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                      │
│   SCORE           CLASSIFICATION        COLOR                       │
│   ─────           ──────────────        ─────                       │
│   ≥ 70            MALICIOUS             Red                         │
│   40 - 69         SUSPICIOUS            Orange                      │
│   < 40            BENIGN                Green                       │
│                                                                      │
│  VISUAL REPRESENTATION (Threat Gauge):                              │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                      │
│              BENIGN        SUSPICIOUS      MALICIOUS                │
│         ┌────────────────┬────────────────┬────────────────┐       │
│         │    0 - 39      │    40 - 69     │    70 - 100    │       │
│         │    GREEN       │    ORANGE      │      RED       │       │
│         └────────────────┴────────────────┴────────────────┘       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 4. Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         DATA FLOW DIAGRAM                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────┐                                                │
│  │ USER INPUT      │                                                │
│  │ • File dialog   │                                                │
│  │ • Drag & drop   │                                                │
│  │ • Command line  │                                                │
│  │ • Batch mode    │                                                │
│  └────────┬────────┘                                                │
│           │                                                          │
│           ▼                                                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                     MAIN WINDOW                              │   │
│  │                   (Controller)                               │   │
│  │                                                               │   │
│  │  1. Validate file (size, type, permissions)                  │   │
│  │  2. Load file data into memory                               │   │
│  │  3. Create AnalysisWorker thread                             │   │
│  │  4. Emit progress signals                                    │   │
│  │                                                               │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                          │
│           ▼                                                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │               ANALYSIS WORKER (Background Thread)            │   │
│  │                                                               │   │
│  │  ┌─────────────────────────────────────────────────────────┐│   │
│  │  │  STAGE 1: File Identification (5%)                      ││   │
│  │  │  • HashCalculator → MD5, SHA256, SSDEEP, TLSH          ││   │
│  │  └─────────────────────────────────────────────────────────┘│   │
│  │                          │                                    │   │
│  │                          ▼                                    │   │
│  │  ┌─────────────────────────────────────────────────────────┐│   │
│  │  │  STAGE 2: VirusTotal Lookup (15%)                       ││   │
│  │  │  • Check SHA256 against VT database                     ││   │
│  │  │  • Retrieve detection count & engine results            ││   │
│  │  └─────────────────────────────────────────────────────────┘│   │
│  │                          │                                    │   │
│  │                          ▼                                    │   │
│  │  ┌─────────────────────────────────────────────────────────┐│   │
│  │  │  STAGE 3: Static Analysis (20-60%)                      ││   │
│  │  │  • EntropyAnalyzer → Entropy calculation                ││   │
│  │  │  • StringExtractor → String extraction & categorization ││   │
│  │  │  • PEAnalyzer → Headers, sections, imports, exports     ││   │
│  │  │  • YaraEngine → Rule matching                           ││   │
│  │  └─────────────────────────────────────────────────────────┘│   │
│  │                          │                                    │   │
│  │                          ▼                                    │   │
│  │  ┌─────────────────────────────────────────────────────────┐│   │
│  │  │  STAGE 4: Behavioral Analysis (70%)                     ││   │
│  │  │  • BehaviorAnalyzer → API pattern detection             ││   │
│  │  │  • Risk indicator calculation                           ││   │
│  │  └─────────────────────────────────────────────────────────┘│   │
│  │                          │                                    │   │
│  │                          ▼                                    │   │
│  │  ┌─────────────────────────────────────────────────────────┐│   │
│  │  │  STAGE 5: Disassembly (80%)                             ││   │
│  │  │  • Disassembler → Entry point detection                 ││   │
│  │  │  • RVA to file offset conversion                        ││   │
│  │  │  • Suspicious instruction highlighting                  ││   │
│  │  └─────────────────────────────────────────────────────────┘│   │
│  │                          │                                    │   │
│  │                          ▼                                    │   │
│  │  ┌─────────────────────────────────────────────────────────┐│   │
│  │  │  STAGE 6: ML Classification (90%)                       ││   │
│  │  │  • FeatureExtractor → 100+ features                     ││   │
│  │  │  • MalwareClassifier → Ensemble prediction              ││   │
│  │  │  • Confidence scoring                                   ││   │
│  │  └─────────────────────────────────────────────────────────┘│   │
│  │                          │                                    │   │
│  │                          ▼                                    │   │
│  │  ┌─────────────────────────────────────────────────────────┐│   │
│  │  │  STAGE 7: Threat Scoring (95%)                          ││   │
│  │  │  • Combine all analysis results                         ││   │
│  │  │  • Calculate weighted threat score                      ││   │
│  │  │  • Determine final classification                       ││   │
│  │  └─────────────────────────────────────────────────────────┘│   │
│  │                                                               │   │
│  └─────────────────────────────────────────────────────────────┘   │
│           │                                                          │
│           ▼                                                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    OUTPUT & STORAGE                          │   │
│  │                                                               │   │
│  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐   │   │
│  │  │   Database    │  │      UI       │  │    Export     │   │   │
│  │  │   (SQLite)    │  │   Display     │  │    (JSON)     │   │   │
│  │  │               │  │               │  │               │   │   │
│  │  │ • samples     │  │ • Dashboard   │  │ • Reports     │   │   │
│  │  │ • analyses    │  │ • Analysis    │  │ • IoCs        │   │   │
│  │  │ • yara_match  │  │ • Hex view    │  │ • CSV         │   │   │
│  │  │ • strings     │  │ • Disasm      │  │               │   │   │
│  │  │ • network_ioc │  │ • Strings     │  │               │   │   │
│  │  └───────────────┘  └───────────────┘  └───────────────┘   │   │
│  │                                                               │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Installation

### Prerequisites

- **Python 3.10+** (3.11 or 3.12 recommended)
- **Windows 10/11** or **Linux** (Ubuntu 20.04+)
- **4GB RAM minimum** (8GB recommended)
- **500MB disk space**

### Step 1: Clone Repository

```bash
git clone https://github.com/yourusername/ai-cerberus.git
cd ai-cerberus
```

### Step 2: Create Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
# Core dependencies
pip install -r requirements.txt

# Optional: TensorFlow for neural network classifier
pip install tensorflow>=2.13.0

# Optional: YARA (if not included)
pip install yara-python
```

### Step 4: Initialize Database

```bash
# Database is auto-created on first run
python main.py --init
```

### Step 5: Configure API Keys (Optional)

Edit `config.yaml`:

```yaml
integrations:
  virustotal:
    api_key: "YOUR_VIRUSTOTAL_API_KEY"
    enabled: true
```

### Step 6: Run Application

```bash
python main.py
```

---

## Quick Start

### Method 1: GUI Launch

```bash
python main.py
```

### Method 2: Analyze File Directly

```bash
python main.py /path/to/suspicious_file.exe
```

### Method 3: Drag and Drop

1. Launch the application
2. Drag any file onto the window
3. Analysis starts automatically

### Method 4: Batch Analysis

```bash
python main.py --batch /path/to/samples/directory
```

---

## Usage Guide

### Main Interface

```
┌─────────────────────────────────────────────────────────────────────────┐
│  AI-Cerberus | Advanced Malware Analysis Platform                       │
├─────────────────────────────────────────────────────────────────────────┤
│ ┌────────┐ ┌─────────────────────────────────────────────────────────┐ │
│ │        │ │  [Open] [Folder] [Search...               ] [Settings] │ │
│ │ SIDEBAR│ ├─────────────────────────────────────────────────────────┤ │
│ │        │ │                                                          │ │
│ │ ▸ Dash │ │   ┌─────────────────────────────────────────────────┐   │ │
│ │ ▸ Hist │ │   │           ANALYSIS RESULTS                      │   │ │
│ │ ▸ YARA │ │   │                                                  │   │ │
│ │ ▸ ML   │ │   │  File: malware.exe                               │   │ │
│ │ ▸ VT   │ │   │  Size: 45.2 KB                                  │   │ │
│ │ ▸ Sand │ │   │  Type: PE32 Executable                          │   │ │
│ │ ▸ Plugs│ │   │                                                  │   │ │
│ │        │ │   │  ╔═══════════════════════════════════════════╗   │   │ │
│ │ ─────  │ │   │  ║        THREAT SCORE: 85/100              ║   │   │ │
│ │ ▸ Sett │ │   │  ║                                          ║   │   │ │
│ │ ▸ About│ │   │  ║          ████████████████░░░░            ║   │   │ │
│ │        │ │   │  ║                                          ║   │   │ │
│ │        │ │   │  ║        CLASSIFICATION: MALICIOUS         ║   │   │ │
│ │        │ │   │  ╚═══════════════════════════════════════════╝   │   │ │
│ │        │ │   │                                                  │   │ │
│ │        │ │   │  TABS: [Overview][PE Info][Imports][YARA][BEH]  │   │ │
│ │        │ │   │        [Disasm][Strings][Hex][ML]               │   │ │
│ │        │ │   │                                                  │   │ │
│ │        │ │   └─────────────────────────────────────────────────┘   │ │
│ │        │ │                                                          │ │
│ └────────┘ └─────────────────────────────────────────────────────────┘ │
│ ┌─────────────────────────────────────────────────────────────────────┐│
│ │ Status: Analysis complete | Samples: 156 | VT: Connected            ││
│ └─────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────┘
```

### Analysis Tabs

| Tab | Description |
|-----|-------------|
| **Overview** | File info, threat score, quick summary |
| **PE Info** | Headers, sections, characteristics |
| **Imports** | Imported DLLs and functions |
| **YARA** | Matched YARA rules with details |
| **Behavioral** | Detected behaviors and risk indicators |
| **Disasm** | Disassembled code with suspicious highlighting |
| **Strings** | Extracted strings by category |
| **Hex** | Raw hex dump with offset navigation |
| **ML** | ML classification details and confidence |

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+O` | Open file |
| `Ctrl+Shift+O` | Open folder (batch) |
| `Ctrl+F` | Focus search |
| `Ctrl+S` | Save report |
| `Ctrl+,` | Settings |
| `F5` | Re-analyze current file |
| `Esc` | Cancel analysis |

---

## Configuration

### config.yaml

```yaml
# AI-Cerberus Configuration

# Analysis Settings
analysis:
  entropy_block_size: 256
  max_file_size: 104857600  # 100MB
  timeout: 300
  yara_timeout: 60
  max_strings: 10000
  max_instructions: 50000

# User Interface
ui:
  theme: "dark"
  font_family: "Segoe UI"
  font_size: 13
  window_width: 1600
  window_height: 1000

# Machine Learning
ml:
  confidence_threshold: 0.7
  models:
    random_forest:
      n_estimators: 100
      max_depth: 15
    gradient_boosting:
      n_estimators: 100
    neural_network:
      enabled: true

# Integrations
integrations:
  virustotal:
    api_key: ""
    enabled: true
    rate_limit: 4  # requests per minute

  hybrid_analysis:
    api_key: ""
    enabled: false

  custom_sandbox:
    enabled: false
    host: ""
    port: 22
    username: ""
    key_path: ""

# Database
database:
  path: "~/.malware_analyzer/analysis.db"
  pool_size: 5

# Logging
logging:
  level: "INFO"
  format: "json"
  file: "~/.malware_analyzer/logs/cerberus.log"
  max_size: 52428800  # 50MB
  backup_count: 5
```

---

## API Reference

### Core Analyzers

```python
from src.core import (
    HashCalculator,
    EntropyAnalyzer,
    StringExtractor,
    PEAnalyzer,
    YaraEngine,
    BehaviorAnalyzer,
    Disassembler,
)

# Hash calculation
hasher = HashCalculator()
result = hasher.analyze(file_path, data)
print(result.sha256, result.md5, result.ssdeep)

# Entropy analysis
entropy = EntropyAnalyzer()
result = entropy.analyze(file_path, data)
print(result.overall_entropy, result.assessment)

# String extraction
strings = StringExtractor()
result = strings.analyze(file_path, data)
print(result.strings, result.suspicious_strings)

# PE analysis
pe = PEAnalyzer()
result = pe.analyze(file_path, data)
print(result.sections, result.imports, result.entry_point)

# YARA scanning
yara = YaraEngine()
matches = yara.analyze(file_path, data)
for match in matches:
    print(match.rule_name, match.severity)

# Behavioral analysis
behavior = BehaviorAnalyzer()
result = behavior.analyze(file_path, data, imports=import_list)
print(result.indicators, result.risk_score)

# Disassembly
disasm = Disassembler(max_instructions=50000)
result = disasm.analyze(file_path, data, architecture="x64", offset=entry_point)
for insn in result.instructions:
    print(f"{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
```

### ML Classification

```python
from src.ml import MalwareClassifier, FeatureExtractor

# Extract features
extractor = FeatureExtractor()
features = extractor.extract(file_path, analysis_results)

# Classify
classifier = MalwareClassifier()
result = classifier.classify(file_path, data)
print(result.classification)  # benign, suspicious, malicious
print(result.confidence)      # 0.0 - 1.0
print(result.probabilities)   # {'benign': 0.1, 'suspicious': 0.2, 'malicious': 0.7}
```

### Database Operations

```python
from src.database import get_repository

repo = get_repository()

# Save sample
with repo.session_scope() as session:
    sample = Sample(
        sha256=hash_result.sha256,
        classification="malicious",
        threat_score=85,
    )
    session.add(sample)

# Query samples
samples = repo.get_samples_by_classification("malicious")
sample = repo.get_sample_by_hash(sha256)
```

---

## Development

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=src tests/

# Run specific test file
pytest tests/test_analyzers.py
```

### Code Style

```bash
# Format code
black src/

# Sort imports
isort src/

# Lint
flake8 src/
```

### Building Executable

```bash
# Windows executable
pyinstaller --name "AI-Cerberus" \
            --icon "resources/icons/cerberus.ico" \
            --windowed \
            --add-data "resources;resources" \
            --add-data "config.yaml;." \
            main.py
```

### Creating Plugin

```python
# plugins/my_plugin.py
from src.plugins import BasePlugin

class MyPlugin(BasePlugin):
    name = "My Custom Plugin"
    version = "1.0.0"
    description = "Custom analysis plugin"

    def analyze(self, file_path, data, results):
        # Custom analysis logic
        custom_result = self.custom_analysis(data)
        results["my_plugin"] = custom_result
        return results

    def custom_analysis(self, data):
        # Implementation
        pass
```

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| **TensorFlow not found** | `pip install tensorflow>=2.13.0` |
| **YARA rules not loading** | Check `resources/yara_rules/` directory |
| **VirusTotal errors** | Verify API key in `config.yaml` |
| **Database locked** | Close other instances, delete `.db-journal` |
| **Out of memory** | Reduce `max_instructions` in config |
| **Icon not showing** | Regenerate with `python create_icon_simple.py` |

### Performance Tuning

```yaml
# For large files (config.yaml)
analysis:
  max_instructions: 25000  # Reduce for faster analysis
  max_strings: 5000        # Limit string extraction
  timeout: 600             # Increase timeout
```

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

### Development Setup

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open Pull Request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- **Capstone Engine** - Disassembly framework
- **YARA** - Pattern matching engine
- **scikit-learn** - Machine learning library
- **PyQt6** - GUI framework
- **pefile** - PE file parsing
- **VirusTotal** - Threat intelligence API

---

## Contact

- **Project**: AI-Cerberus
- **Author**: NW Chanaka Lasantha
- **GitHub**: [github.com/yourusername/ai-cerberus](https://github.com/yourusername/ai-cerberus)

---

<p align="center">
  <b>AI-Cerberus</b> - The Three-Headed Guardian Against Malicious Code
  <br>
  <i>"Guarding your systems from the gates of digital threats"</i>
</p>

---

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║     "In Greek mythology, Cerberus guards the gates of the Underworld,       ║
║      preventing the dead from leaving. In cybersecurity, AI-Cerberus        ║
║      guards your systems, preventing malware from entering."                 ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```
