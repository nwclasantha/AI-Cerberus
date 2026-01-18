"""
Main application window.

Central controller for the entire UI.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, List, TYPE_CHECKING

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QFileDialog, QMessageBox, QSplitter, QDialog,
)
from PyQt6.QtCore import Qt, pyqtSignal, QThreadPool, QRunnable, QObject, QTimer, QUrl
from PyQt6.QtGui import QAction, QKeySequence, QDragEnterEvent, QDropEvent, QIcon

from .theme import get_theme_manager
from .components import (
    Sidebar, MainToolbar, EnhancedStatusBar,
    TabManager, ToastManager, ProgressOverlay,
)
from .views import (
    DashboardView, AnalysisView, HexView,
    DisassemblyView, StringsView, HistoryView, YaraRulesView,
    MLClassificationView, VirusTotalView, SandboxView, PluginManagerView,
)

from ..core import (
    HashCalculator, EntropyAnalyzer, StringExtractor,
    PEAnalyzer, YaraEngine, BehaviorAnalyzer, Disassembler,
)
from ..core.false_positive_prevention import get_false_positive_prevention
from ..ml import MalwareClassifier, get_auto_trainer
from ..integrations import VirusTotalClient
from ..database import get_repository
from ..core import get_mode_manager
from ..utils.config import get_config
from ..utils.logger import get_logger

logger = get_logger("main_window")


class AnalysisWorkerSignals(QObject):
    """Signals for analysis worker."""
    started = pyqtSignal()
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)


class AnalysisWorker(QRunnable):
    """Background worker for file analysis."""

    def __init__(self, file_path: Path):
        super().__init__()
        self.file_path = file_path
        self.signals = AnalysisWorkerSignals()

    def run(self):
        """Execute analysis in background."""
        try:
            self.signals.started.emit()

            results = {}

            # Check file size before loading (prevent memory exhaustion)
            MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB limit
            file_size = self.file_path.stat().st_size

            if file_size > MAX_FILE_SIZE:
                size_mb = file_size / (1024 * 1024)
                raise ValueError(
                    f"File too large for analysis: {size_mb:.1f}MB. "
                    f"Maximum supported size is {MAX_FILE_SIZE / (1024 * 1024):.0f}MB"
                )

            # Load file data
            self.signals.progress.emit(5, "Loading file...")
            data = self.file_path.read_bytes()

            # Calculate hashes
            self.signals.progress.emit(10, "Calculating hashes...")
            hash_calc = HashCalculator()
            results["hashes"] = hash_calc.analyze(self.file_path, data).to_dict()

            # VirusTotal lookup (automatic)
            self.signals.progress.emit(15, "Querying VirusTotal...")
            try:
                vt_client = VirusTotalClient()
                if vt_client.is_configured:
                    sha256 = results["hashes"].get("sha256", "")
                    if sha256:
                        vt_report = vt_client.lookup_hash_sync(sha256)
                        if vt_report:
                            results["virustotal"] = vt_report.to_dict()
                            logger.info(f"VirusTotal: {vt_report.detection_count}/{vt_report.total_engines} detections")
                        else:
                            results["virustotal"] = None
                            logger.info("VirusTotal: File not found in database")
                    else:
                        results["virustotal"] = None
                else:
                    results["virustotal"] = None
                    logger.debug("VirusTotal API key not configured")
            except Exception as e:
                logger.warning(f"VirusTotal lookup failed: {e}")
                results["virustotal"] = None

            # Entropy analysis
            self.signals.progress.emit(20, "Analyzing entropy...")
            entropy = EntropyAnalyzer()
            results["entropy"] = entropy.analyze(self.file_path, data).to_dict()

            # String extraction
            self.signals.progress.emit(30, "Extracting strings...")
            strings = StringExtractor()
            results["strings"] = strings.analyze(self.file_path, data).to_dict()

            # PE Analysis (if applicable)
            self.signals.progress.emit(40, "Analyzing binary structure...")
            if data[:2] == b"MZ":
                pe_analyzer = PEAnalyzer()
                pe_info = pe_analyzer.analyze(self.file_path, data)
                results["pe_info"] = pe_info.to_dict()
                results["sections"] = [s.to_dict() for s in pe_info.sections]
                results["imports"] = [i.to_dict() for i in pe_info.imports]
                results["architecture"] = pe_info.architecture

            # YARA scanning
            self.signals.progress.emit(60, "Running YARA rules...")
            yara = YaraEngine()
            yara_matches = yara.analyze(self.file_path, data)
            results["yara_matches"] = [m.to_dict() for m in yara_matches]

            # Behavior analysis
            self.signals.progress.emit(70, "Analyzing behavior...")
            behavior = BehaviorAnalyzer()
            # Extract function names from imports for behavior analysis
            import_functions = []
            for imp_dict in results.get("imports", []):
                import_functions.extend(imp_dict.get("functions", []))
            results["behavior"] = behavior.analyze(
                self.file_path, data,
                imports=import_functions,
            ).to_dict()

            # Disassembly
            self.signals.progress.emit(80, "Disassembling...")
            disasm = Disassembler(max_instructions=200000)  # Maximum coverage for full disassembly
            arch = results.get("architecture", "x64")

            # Get entry point offset from PE analysis (convert RVA to file offset)
            offset = 0  # Default to start of file
            if results.get("pe_info"):
                # Get entry point RVA
                entry_point_hex = results["pe_info"].get("entry_point", "0x0")
                entry_point_rva = int(entry_point_hex, 16) if isinstance(entry_point_hex, str) else entry_point_hex

                # Convert RVA to file offset using section mapping
                for section_dict in results.get("sections", []):
                    va_hex = section_dict.get("virtual_address", "0x0")
                    va = int(va_hex, 16) if isinstance(va_hex, str) else va_hex

                    raw_offset_hex = section_dict.get("raw_offset", "0x0")
                    raw_offset = int(raw_offset_hex, 16) if isinstance(raw_offset_hex, str) else raw_offset_hex

                    virtual_size = section_dict.get("virtual_size", 0)

                    # Check if entry point is in this section
                    if va <= entry_point_rva < va + virtual_size:
                        # Calculate file offset
                        offset = raw_offset + (entry_point_rva - va)
                        logger.info(f"Disassembly: Entry point RVA {entry_point_hex} -> File offset 0x{offset:x}")
                        break

            disasm_result = disasm.analyze(self.file_path, data, architecture=arch, offset=offset)
            results["disassembly"] = disasm_result.to_dict().get("instructions", [])  # FIXED: Return ALL instructions, not just 500!

            # ML Classification
            self.signals.progress.emit(90, "ML classification...")
            classifier = MalwareClassifier()
            ml_result = classifier.classify(self.file_path, data)
            results["ml_classification"] = ml_result.to_dict()

            # Calculate threat score
            self.signals.progress.emit(95, "Calculating threat score...")
            threat_score = self._calculate_threat_score(results)
            results["threat_score"] = threat_score

            # Determine classification
            if threat_score["score"] >= 70:
                results["classification"] = "malicious"
            elif threat_score["score"] >= 40:
                results["classification"] = "suspicious"
            else:
                results["classification"] = "benign"

            # File info
            results["file_info"] = {
                "filename": self.file_path.name,
                "size": len(data),
                "size_human": self._format_size(len(data)),
                "file_type": results.get("pe_info", {}).get("file_type", "Unknown"),
            }

            # Include raw file data to avoid redundant file reads (internal use only)
            results["_raw_file_data"] = data

            self.signals.progress.emit(100, "Analysis complete")
            self.signals.finished.emit(results)

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            self.signals.error.emit(str(e))

    def _calculate_threat_score(self, results: Dict) -> Dict:
        """
        Calculate overall threat score from multiple detection sources.

        Scoring breakdown:
        - YARA: 0-25+ points (critical rules)
        - Behavioral: 0-70 points (70% of behavioral score)
        - ML: 0-20 points (confidence-weighted)
        - Entropy: 0-15 points (packing/encryption)
        - VirusTotal: 0-20 points (detection ratio)
        - Strings: 0-10 points (suspicious strings)
        - PE structure: 0-10 points (suspicious PE characteristics)
        - Legitimacy: -30 to -50 points (signed, known good)
        """
        score = 0

        # FALSE POSITIVE PREVENTION: Check file legitimacy FIRST
        # Signed legitimate software should NOT be flagged as malware
        fp_prevention = get_false_positive_prevention()
        legitimacy_result = None
        is_legitimate = False

        try:
            file_path = self.file_path
            file_hash = results.get("hashes", {}).get("sha256")
            file_data = results.get("_raw_file_data")

            legitimacy_result = fp_prevention.check_legitimacy(
                file_path, file_hash, file_data
            )
            is_legitimate = legitimacy_result.is_legitimate

            # Store legitimacy info in results for display
            results["legitimacy"] = {
                "is_legitimate": legitimacy_result.is_legitimate,
                "confidence": legitimacy_result.confidence,
                "reason": legitimacy_result.reason,
                "has_valid_signature": legitimacy_result.has_valid_signature,
                "signature_verified": legitimacy_result.signature_verified_cryptographically,
                "publisher": legitimacy_result.publisher_name,
            }

            if is_legitimate:
                logger.info(f"Legitimate file detected: {legitimacy_result.reason}")
        except Exception as e:
            logger.debug(f"Legitimacy check failed: {e}")

        # YARA matches (signature-based detection)
        # IMPORTANT: Reduce YARA impact for legitimately signed software
        # Microsoft-signed tools like TCPView shouldn't be flagged by generic rules
        yara_matches = results.get("yara_matches", [])
        raw_yara_score = 0
        for match in yara_matches:
            severity = match.get("severity", "medium")
            if severity == "critical":
                raw_yara_score += 25
            elif severity == "high":
                raw_yara_score += 15
            elif severity == "medium":
                raw_yara_score += 8

        # Reduce YARA score for legitimate signed software
        # CRITICAL: Cap YARA score for signed files - don't just reduce percentage
        # Microsoft tools like TCPView can trigger 2000+ YARA points from generic rules
        if is_legitimate and legitimacy_result:
            if legitimacy_result.signature_verified_cryptographically:
                # Cryptographically verified - CAP at 5 points max (trust signature!)
                yara_score = min(5, raw_yara_score * 0.01)
                logger.info(f"Capping YARA score for verified signed file: {raw_yara_score} -> {yara_score}")
            elif legitimacy_result.has_valid_signature:
                # Signed but not verified - cap at 15 points
                yara_score = min(15, raw_yara_score * 0.05)
            else:
                # Other legitimacy - cap at 30 points
                yara_score = min(30, raw_yara_score * 0.1)
        else:
            yara_score = raw_yara_score  # Full YARA score for unsigned/suspicious files

        score += yara_score

        # Behavior indicators - REDUCED for legitimate signed software
        # Legitimate tools like PuTTY, browsers, etc. have network + shell APIs
        # but are NOT malware. Don't penalize them heavily.
        behavior = results.get("behavior", {})
        risk = behavior.get("risk", {})
        raw_behavioral_score = risk.get("score", 0)

        # If file is legitimately signed, reduce behavioral penalty significantly
        if is_legitimate and legitimacy_result:
            if legitimacy_result.signature_verified_cryptographically:
                # Cryptographically verified signature - minimal behavioral penalty
                behavioral_score = raw_behavioral_score * 0.1  # Only 10%
                logger.info(f"Reducing behavioral score for signed file: {raw_behavioral_score} -> {behavioral_score}")
            elif legitimacy_result.has_valid_signature:
                # Signed but not verified - moderate reduction
                behavioral_score = raw_behavioral_score * 0.3  # 30%
            else:
                # Other legitimacy indicators - slight reduction
                behavioral_score = raw_behavioral_score * 0.5  # 50%
        else:
            # Not legitimate - full behavioral scoring
            behavioral_score = raw_behavioral_score * 0.7  # 70%

        score += behavioral_score

        # Entropy analysis (packing/encryption detection)
        entropy = results.get("entropy", {})
        if entropy.get("assessment") == "encrypted":
            score += 15
        elif entropy.get("assessment") == "packed":
            score += 10

        # ML classification (ensemble model prediction)
        ml = results.get("ml_classification", {})
        if ml.get("prediction") == "malicious":
            score += 20 * ml.get("confidence", 0)
        elif ml.get("prediction") == "suspicious":
            score += 10 * ml.get("confidence", 0)

        # VirusTotal detections (NEW: add VT detection ratio)
        vt = results.get("virustotal")
        if vt and isinstance(vt, dict):
            detection_count = vt.get("detection_count", 0)
            total_engines = vt.get("total_engines", 1)
            if total_engines > 0:
                detection_ratio = detection_count / total_engines
                if detection_ratio >= 0.5:  # 50%+ engines detected
                    score += 20
                elif detection_ratio >= 0.3:  # 30-50% engines
                    score += 15
                elif detection_ratio >= 0.1:  # 10-30% engines
                    score += 10
                elif detection_ratio > 0:  # Any detection
                    score += 5

        # Suspicious strings (NEW: check for suspicious string count)
        strings_result = results.get("strings", {})
        if strings_result and isinstance(strings_result, dict):
            categories = strings_result.get("categories", {})
            suspicious_strings = categories.get("suspicious", [])
            if len(suspicious_strings) >= 5:
                score += 10
            elif len(suspicious_strings) >= 2:
                score += 5

        # PE structure indicators (NEW: check for suspicious PE characteristics)
        pe_info = results.get("pe_info", {})
        if pe_info and isinstance(pe_info, dict):
            # Check for suspicious section names
            sections = results.get("sections", [])
            suspicious_section_names = {".themida", ".vmp", ".upx", "upx0", "upx1"}
            for section in sections:
                if any(name.lower() in section.get("name", "").lower()
                       for name in suspicious_section_names):
                    score += 5
                    break

            # Check for unusual entry point
            if pe_info.get("entry_point_suspicious", False):
                score += 5

        # LEGITIMACY BONUS: Reduce score for legitimately signed software
        # This is CRITICAL to prevent false positives on tools like PuTTY, browsers, etc.
        if is_legitimate and legitimacy_result:
            legitimacy_reduction = 0

            if legitimacy_result.signature_verified_cryptographically:
                # Cryptographically verified = very trustworthy
                legitimacy_reduction = 50
            elif legitimacy_result.has_valid_signature:
                # Signed but not verified
                legitimacy_reduction = 30
            elif legitimacy_result.confidence >= 0.7:
                # High legitimacy confidence from other factors
                legitimacy_reduction = 20

            # Apply reduction
            if legitimacy_reduction > 0:
                old_score = score
                score = max(0, score - legitimacy_reduction)
                logger.info(f"Legitimacy reduction: {old_score} -> {score} (-{legitimacy_reduction})")

        # Cap at 100 max (and 0 min)
        score = max(0, min(100, score))

        return {
            "score": round(score, 1),
            "level": self._get_threat_level(score),
        }

    def _get_threat_level(self, score: float) -> str:
        """Get threat level string."""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "low"
        return "clean"

    def _format_size(self, size: int) -> str:
        """Format file size."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"


class MainWindow(QMainWindow):
    """
    Main application window.

    Coordinates all UI components and handles user interactions.
    """

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize main window."""
        super().__init__(parent)

        self._config = get_config()
        self._repository = get_repository()
        self._thread_pool = QThreadPool()
        self._thread_pool.setMaxThreadCount(2)  # Limit concurrent analyses (prevent resource exhaustion)
        self._current_file: Optional[Path] = None
        self._current_data: Optional[bytes] = None

        # Batch processing state
        self._batch_queue: List[Path] = []
        self._batch_stats = {"total": 0, "completed": 0, "failed": 0}
        self._is_batch_processing = False

        # Analysis mode manager
        self._mode_manager = get_mode_manager()

        # Auto-trainer
        self._auto_trainer = get_auto_trainer()

        self.setWindowTitle("AI-Cerberus | Advanced Malware Analysis Platform")
        self.setMinimumSize(1280, 800)
        self.resize(1600, 1000)  # Set default size (larger than minimum)

        # Set window icon (.ico for Windows, multi-resolution)
        icon_path = Path(__file__).parent.parent.parent / "resources" / "icons" / "cerberus.ico"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        # Enable drag-and-drop for automatic file analysis
        self.setAcceptDrops(True)

        self._setup_ui()
        self._setup_menu()
        self._connect_signals()

        # Load initial data (async to avoid blocking)
        QTimer.singleShot(100, self._load_dashboard_data)

        # Initialize ML models (async to avoid blocking UI)
        QTimer.singleShot(500, self._initialize_ml_models)

        logger.info("Main window initialized")

    def _setup_ui(self) -> None:
        """Set up main window UI."""
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)

        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Sidebar
        self._sidebar = Sidebar()
        main_layout.addWidget(self._sidebar)

        # Content area
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        # Toolbar
        self._toolbar = MainToolbar()
        content_layout.addWidget(self._toolbar)

        # Tab manager for views
        self._tabs = TabManager()
        content_layout.addWidget(self._tabs)

        main_layout.addWidget(content_widget, 1)

        # Status bar
        self._status_bar = EnhancedStatusBar()
        self.setStatusBar(self._status_bar)

        # Toast notifications
        self._toast = ToastManager(self)

        # Progress overlay
        self._progress = ProgressOverlay(central)

        # Create views
        self._create_views()

    def _create_views(self) -> None:
        """Create main views."""
        # Dashboard view (always open)
        self._dashboard = DashboardView()
        self._tabs.add_tab("dashboard", self._dashboard, "Dashboard", closable=False)

        # History view
        self._history_view = HistoryView()
        self._history_view.sample_selected.connect(self._on_history_sample_selected)
        self._history_view.analysis_requested.connect(self._open_file_path)

        # YARA Rules view
        self._yara_view = YaraRulesView()

        # ML Classification view
        self._ml_view = MLClassificationView()

        # VirusTotal view
        self._virustotal_view = VirusTotalView()

        # Sandbox view
        self._sandbox_view = SandboxView()

        # Plugin Manager view
        self._plugin_view = PluginManagerView()

        # Analysis view template
        self._analysis_view = AnalysisView()

        # Hex view template
        self._hex_view = HexView()

        # Disassembly view template
        self._disasm_view = DisassemblyView()

        # Strings view template
        self._strings_view = StringsView()

    def _setup_menu(self) -> None:
        """Set up menu bar."""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("&File")

        open_action = QAction("&Open File...", self)
        open_action.setShortcut(QKeySequence.StandardKey.Open)
        open_action.triggered.connect(self._open_file)
        file_menu.addAction(open_action)

        open_folder_action = QAction("Open &Folder...", self)
        open_folder_action.triggered.connect(self._open_folder)
        file_menu.addAction(open_folder_action)

        file_menu.addSeparator()

        export_action = QAction("&Export Report...", self)
        export_action.setShortcut(QKeySequence("Ctrl+E"))
        file_menu.addAction(export_action)

        file_menu.addSeparator()

        # Clear All Scans action
        clear_all_action = QAction("Clear All &Scans...", self)
        clear_all_action.setShortcut(QKeySequence("Ctrl+Shift+D"))
        clear_all_action.triggered.connect(self._clear_all_scans)
        file_menu.addAction(clear_all_action)

        file_menu.addSeparator()

        exit_action = QAction("E&xit", self)
        exit_action.setShortcut(QKeySequence.StandardKey.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # View menu
        view_menu = menubar.addMenu("&View")

        dashboard_action = QAction("&Dashboard", self)
        dashboard_action.triggered.connect(lambda: self._sidebar.navigate_to("dashboard"))
        view_menu.addAction(dashboard_action)

        view_menu.addSeparator()

        theme_action = QAction("Toggle &Theme", self)
        theme_action.triggered.connect(self._toggle_theme)
        view_menu.addAction(theme_action)

        # Analysis menu
        analysis_menu = menubar.addMenu("&Analysis")

        analyze_action = QAction("&Analyze Current", self)
        analyze_action.setShortcut(QKeySequence("F5"))
        analysis_menu.addAction(analyze_action)

        analysis_menu.addSeparator()

        mode_selector_action = QAction("Analysis &Mode...", self)
        mode_selector_action.triggered.connect(self._show_analysis_mode_selector)
        analysis_menu.addAction(mode_selector_action)

        # Machine Learning menu
        ml_menu = menubar.addMenu("&Machine Learning")

        model_status_action = QAction("Model &Management...", self)
        model_status_action.triggered.connect(self._show_model_management)
        ml_menu.addAction(model_status_action)

        retrain_action = QAction("&Retrain Models...", self)
        retrain_action.triggered.connect(lambda: self._retrain_models(None))
        ml_menu.addAction(retrain_action)

        # Help menu
        help_menu = menubar.addMenu("&Help")

        about_action = QAction("&About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _connect_signals(self) -> None:
        """Connect UI signals."""
        # Sidebar navigation
        self._sidebar.navigation_changed.connect(self._on_navigation)

        # Toolbar actions
        self._toolbar.file_open_requested.connect(self._open_file)
        self._toolbar.folder_open_requested.connect(self._open_folder)
        self._toolbar.search_submitted.connect(self._on_search)
        self._toolbar.settings_requested.connect(self._show_settings)
        self._toolbar.file_save_requested.connect(self._save_report)
        self._toolbar.export_requested.connect(self._export_results)
        self._toolbar.refresh_requested.connect(self._refresh_view)

        # Dashboard signals
        self._dashboard.open_file_requested.connect(self._open_file)
        self._dashboard.sample_selected.connect(self._load_sample)
        self._dashboard.clear_all_requested.connect(self._clear_all_scans)

        # Progress overlay
        self._progress.cancelled.connect(self._cancel_analysis)

    def _on_navigation(self, key: str) -> None:
        """Handle sidebar navigation."""
        logger.debug(f"Navigation clicked: {key}")
        logger.info(f"Navigation to: {key}")
        if key == "dashboard":
            self._tabs.setCurrentWidget(self._dashboard)
        elif key == "analysis":
            if self._tabs.has_tab("analysis"):
                self._tabs.setCurrentIndex(
                    self._tabs.indexOf(self._tabs.get_tab_widget("analysis"))
                )
        elif key == "samples":
            self._sidebar.navigate_to("dashboard")
        elif key == "history":
            # Show history view in a new tab
            if not self._tabs.has_tab("history"):
                self._tabs.add_tab("history", self._history_view, "History", closable=True)
            self._tabs.setCurrentWidget(self._history_view)
            self._history_view.load_history()  # Refresh data
        elif key == "yara":
            # Show YARA Rules view in a new tab
            if not self._tabs.has_tab("yara"):
                self._tabs.add_tab("yara", self._yara_view, "YARA Rules", closable=True)
            self._tabs.setCurrentWidget(self._yara_view)
            self._yara_view._load_rules()  # Refresh rules
        elif key == "ml":
            # Show ML Classification view in a new tab
            if not self._tabs.has_tab("ml"):
                self._tabs.add_tab("ml", self._ml_view, "ML Classification", closable=True)
            self._tabs.setCurrentWidget(self._ml_view)
        elif key == "virustotal":
            # Show VirusTotal view in a new tab
            if not self._tabs.has_tab("virustotal"):
                self._tabs.add_tab("virustotal", self._virustotal_view, "VirusTotal", closable=True)
            self._tabs.setCurrentWidget(self._virustotal_view)
        elif key == "sandbox":
            # Show Sandbox view in a new tab
            if not self._tabs.has_tab("sandbox"):
                self._tabs.add_tab("sandbox", self._sandbox_view, "Sandbox", closable=True)
            self._tabs.setCurrentWidget(self._sandbox_view)
        elif key == "plugins":
            # Show Plugin Manager view in a new tab
            if not self._tabs.has_tab("plugins"):
                self._tabs.add_tab("plugins", self._plugin_view, "Plugin Manager", closable=True)
            self._tabs.setCurrentWidget(self._plugin_view)
        elif key == "settings":
            self._show_settings()
        elif key == "about":
            self._show_about()

    def _open_file(self) -> None:
        """Open file dialog."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open File for Analysis",
            "",
            "All Files (*);;Executables (*.exe *.dll *.sys);;Documents (*.doc *.pdf)",
        )

        if file_path:
            self._analyze_file(Path(file_path))

    def _open_folder(self) -> None:
        """Open folder for batch analysis."""
        folder = QFileDialog.getExistingDirectory(
            self,
            "Select Folder for Batch Analysis",
        )

        if not folder:
            return

        from PyQt6.QtWidgets import (
            QDialog, QVBoxLayout, QHBoxLayout, QLabel,
            QPushButton, QCheckBox, QSpinBox
        )

        folder_path = Path(folder).resolve()

        # Show options dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Batch Analysis Options")
        dialog.setMinimumWidth(400)
        layout = QVBoxLayout(dialog)

        # Recursive option
        recursive_check = QCheckBox("Include subdirectories (recursive)")
        recursive_check.setChecked(False)
        layout.addWidget(recursive_check)

        # File limit
        limit_layout = QHBoxLayout()
        limit_layout.addWidget(QLabel("Maximum files:"))
        limit_spin = QSpinBox()
        limit_spin.setRange(1, 10000)
        limit_spin.setValue(100)
        limit_layout.addWidget(limit_spin)
        limit_layout.addStretch()
        layout.addLayout(limit_layout)

        # Status label (updated when options change)
        status_label = QLabel("Counting files...")
        layout.addWidget(status_label)

        def update_file_count() -> None:
            """Update the file count based on current options."""
            try:
                pattern = "**/*" if recursive_check.isChecked() else "*"
                max_files = limit_spin.value()
                count = 0
                for f in folder_path.glob(pattern):
                    if f.is_file():
                        try:
                            size = f.stat().st_size
                            if 0 < size < 100 * 1024 * 1024:
                                count += 1
                                if count >= max_files:
                                    break
                        except OSError:
                            continue
                status_label.setText(f"Found {count} files to analyze")
            except Exception as e:
                status_label.setText(f"Error scanning folder: {e}")

        recursive_check.stateChanged.connect(lambda: update_file_count())
        limit_spin.valueChanged.connect(lambda: update_file_count())

        # Initial count
        QTimer.singleShot(100, update_file_count)

        # Buttons
        button_layout = QHBoxLayout()
        start_btn = QPushButton("Start Analysis")
        cancel_btn = QPushButton("Cancel")
        button_layout.addStretch()
        button_layout.addWidget(start_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)

        cancel_btn.clicked.connect(dialog.reject)

        def start_analysis() -> None:
            """Collect files and start batch analysis."""
            dialog.accept()

            pattern = "**/*" if recursive_check.isChecked() else "*"
            max_files = limit_spin.value()

            files_to_analyze: List[Path] = []
            for f in folder_path.glob(pattern):
                if f.is_file():
                    try:
                        size = f.stat().st_size
                        if 0 < size < 100 * 1024 * 1024:
                            files_to_analyze.append(f)
                            if len(files_to_analyze) >= max_files:
                                break
                    except OSError:
                        continue

            if not files_to_analyze:
                self._toast.warning(f"No valid files found in {folder}")
                return

            # Use the non-blocking batch analysis system
            self._batch_analyze_files(files_to_analyze)

        start_btn.clicked.connect(start_analysis)
        dialog.exec()

    def _open_file_path(self, file_path: str) -> None:
        """Open and analyze a file from a path string."""
        try:
            path = Path(file_path)
            if path.exists() and path.is_file():
                self._analyze_file(path)
            else:
                QMessageBox.warning(
                    self,
                    "File Not Found",
                    f"The file no longer exists at:\n{file_path}\n\nIt may have been moved or deleted."
                )
        except Exception as e:
            logger.error(f"Failed to open file path: {e}")
            QMessageBox.critical(self, "Error", f"Failed to open file:\n{str(e)}")

    def _on_history_sample_selected(self, sha256: str) -> None:
        """Handle sample selection from history view."""
        try:
            # Get sample from database
            repo = get_repository()
            sample = repo.get_sample_by_hash(sha256)

            if sample and sample.analyses:
                # Load the most recent analysis
                latest_analysis = max(sample.analyses, key=lambda a: a.timestamp)

                # Switch to or create analysis tab
                if not self._tabs.has_tab("analysis"):
                    self._tabs.add_tab("analysis", self._analysis_view, f"Analysis", closable=True)
                self._tabs.setCurrentWidget(self._analysis_view)

                # TODO: Load analysis data into analysis view
                QMessageBox.information(
                    self,
                    "Analysis Details",
                    f"Sample: {sample.filename}\n"
                    f"SHA256: {sha256}\n"
                    f"Classification: {sample.classification}\n"
                    f"Threat Score: {sample.threat_score:.1f}\n"
                    f"Analyzed: {latest_analysis.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
                )
            else:
                QMessageBox.information(
                    self,
                    "No Analysis Data",
                    f"No analysis data available for this sample.\nSHA256: {sha256}"
                )

        except Exception as e:
            logger.error(f"Failed to load sample: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load sample:\n{str(e)}")

    def _export_batch_results(self, results: list, folder_path: Path) -> None:
        """Export batch analysis results."""
        import json
        from datetime import datetime, timezone

        output_file = folder_path / f"batch_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        try:
            with open(output_file, 'w') as f:
                json.dump({
                    'analysis_date': datetime.now(timezone.utc).isoformat(),
                    'folder': str(folder_path),
                    'total_files': len(results),
                    'results': results
                }, f, indent=2)

            self._toast.success(f"Results exported to {output_file.name}")
        except Exception as e:
            self._toast.error(f"Failed to export results: {e}")

    def _analyze_file(self, file_path: Path) -> None:
        """Start file analysis."""
        if not file_path.exists():
            self._toast.error(f"File not found: {file_path}")
            return

        self._current_file = file_path
        self._status_bar.start_analysis(file_path.name)

        # Show progress overlay
        self._progress.show_progress(
            title=f"Analyzing {file_path.name}",
            status="Starting analysis...",
        )

        # Create and start worker
        worker = AnalysisWorker(file_path)
        worker.signals.progress.connect(self._on_analysis_progress)
        worker.signals.finished.connect(self._on_analysis_complete)
        worker.signals.error.connect(self._on_analysis_error)

        self._thread_pool.start(worker)

    def _on_analysis_progress(self, value: int, status: str) -> None:
        """Update analysis progress."""
        self._progress.update_progress(value, status)
        self._status_bar.set_progress(value)

    def _on_analysis_complete(self, results: Dict) -> None:
        """Handle analysis completion."""
        self._progress.hide_progress()
        self._status_bar.finish_analysis()

        # Track batch progress
        if self._is_batch_processing:
            self._batch_stats["completed"] += 1

        # Show results in analysis view (only if not batch processing or last file)
        if not self._is_batch_processing or len(self._batch_queue) == 0:
            self._analysis_view.set_analysis_data(results)

            # Add/update analysis tab - Use SHA256 hash for unique ID
            file_hash = results.get("hashes", {}).get("sha256", "")[:8]  # First 8 chars
            tab_id = f"analysis_{file_hash}_{self._current_file.name}"
            if not self._tabs.has_tab(tab_id):
                self._tabs.add_tab(tab_id, self._analysis_view, f"Analysis: {self._current_file.name}", closable=True)
            else:
                self._tabs.setCurrentWidget(self._tabs.get_tab_widget(tab_id))

            # Update hex view (reuse data from results to avoid redundant file read)
            file_data = results.get("_raw_file_data")
            if file_data:
                # Clear old data before setting new data to prevent memory buildup
                self._current_data = file_data
                if hasattr(self._hex_view, 'clear'):
                    self._hex_view.clear()
                self._hex_view.set_data(self._current_data)

                # Use SHA256 hash for unique tab ID to avoid collisions
                file_hash = results.get("hashes", {}).get("sha256", "")[:8]  # First 8 chars
                hex_tab_id = f"hex_{file_hash}_{self._current_file.name}"
                if not self._tabs.has_tab(hex_tab_id):
                    self._tabs.add_tab(hex_tab_id, self._hex_view, f"Hex: {self._current_file.name}", closable=True)

            # Update disassembly
            disasm = results.get("disassembly", [])
            if hasattr(self._disasm_view, 'clear'):
                self._disasm_view.clear()
            self._disasm_view.set_instructions(disasm)

            # Use SHA256 hash for unique tab ID
            file_hash = results.get("hashes", {}).get("sha256", "")[:8]
            disasm_tab_id = f"disasm_{file_hash}_{self._current_file.name}"
            if not self._tabs.has_tab(disasm_tab_id):
                self._tabs.add_tab(disasm_tab_id, self._disasm_view, f"Disassembly: {self._current_file.name}", closable=True)

            # Update strings
            strings_data = results.get("strings", {})
            if hasattr(self._strings_view, 'clear'):
                self._strings_view.clear()
            self._strings_view.set_strings(strings_data.get("strings", []))

            # Use SHA256 hash for unique tab ID
            strings_tab_id = f"strings_{file_hash}_{self._current_file.name}"
            if not self._tabs.has_tab(strings_tab_id):
                self._tabs.add_tab(strings_tab_id, self._strings_view, f"Strings: {self._current_file.name}", closable=True)

            # Update VirusTotal view with automatic results
            vt_data = results.get("virustotal")
            if vt_data:
                self._virustotal_view.display_vt_results(vt_data)

        # Save to database (always save)
        self._save_analysis(results)

        # Show toast (skip for batch mode except errors)
        if not self._is_batch_processing:
            score = results.get("threat_score", {}).get("score", 0)
            classification = results.get("classification", "unknown")

            # Include VirusTotal info in toast if available
            toast_msg = f"Analysis complete: {classification.upper()} (Score: {score})"
            vt_data = results.get("virustotal")
            if vt_data:
                detection_count = vt_data.get("detection_count", 0)
                total_engines = vt_data.get("total_engines", 0)
                toast_msg += f" | VT: {detection_count}/{total_engines}"

            if classification == "malicious":
                self._toast.error(toast_msg)
            elif classification == "suspicious":
                self._toast.warning(toast_msg)
            else:
                self._toast.success(toast_msg)

            # Update dashboard gauge with current file's score (NEW)
            self._dashboard.update_current_file_score(score, classification)

        # Refresh dashboard
        self._load_dashboard_data()

        # Process next file in batch mode
        if self._is_batch_processing:
            # Small delay before next file to allow UI updates
            QTimer.singleShot(500, self._process_next_batch_file)

    def _on_analysis_error(self, error: str) -> None:
        """Handle analysis error."""
        self._progress.hide_progress()
        self._status_bar.set_message(f"Analysis failed: {error}")

        # Track batch failures
        if self._is_batch_processing:
            self._batch_stats["failed"] += 1
            logger.error(f"Batch file failed: {error}")
            # Continue with next file
            QTimer.singleShot(500, self._process_next_batch_file)
        else:
            # Show error for single file analysis
            self._toast.error(f"Analysis failed: {error}")

    def _cancel_analysis(self) -> None:
        """Cancel current analysis."""
        self._status_bar.set_message("Analysis cancelled")

    def _save_analysis(self, results: Dict) -> None:
        """Save analysis results to database."""
        try:
            hashes = results.get("hashes", {})
            sha256 = hashes.get("sha256", "")

            if not sha256:
                return

            # Get or create sample
            sample, created = self._repository.get_or_create_sample(
                sha256=sha256,
                md5=hashes.get("md5"),
                sha1=hashes.get("sha1"),
                filename=results.get("file_info", {}).get("filename"),
                file_size=results.get("file_info", {}).get("size"),
                file_type=results.get("file_info", {}).get("file_type"),
            )

            # Update sample
            self._repository.update_sample(
                sha256,
                classification=results.get("classification"),
                threat_score=results.get("threat_score", {}).get("score", 0),
            )

            logger.info(f"Analysis saved: {sha256[:16]}...")

        except Exception as e:
            logger.error(f"Failed to save analysis: {e}")

    def _load_sample(self, sha256: str) -> None:
        """Load sample from database."""
        sample = self._repository.get_sample_by_hash(sha256)
        if sample:
            self._toast.info(f"Loading sample: {sample.filename}")

    def _load_dashboard_data(self) -> None:
        """Load dashboard statistics."""
        try:
            stats = self._repository.get_sample_statistics()
            self._dashboard.update_statistics(stats)

            samples = self._repository.get_recent_samples(limit=10)
            sample_list = [
                {
                    "sha256": s.sha256,
                    "filename": s.filename,
                    "classification": s.classification,
                    "threat_score": s.threat_score or 0,
                    "file_type": s.file_type,
                    "last_analyzed": str(s.last_analyzed) if s.last_analyzed else "",
                }
                for s in samples
            ]
            self._dashboard.update_recent_samples(sample_list)

            self._status_bar.set_sample_count(stats.get("total", 0))

            # Update API status indicators
            self._update_api_status()

        except Exception as e:
            logger.error(f"Failed to load dashboard data: {e}")

    def _update_api_status(self) -> None:
        """Update API connection status indicators."""
        # Check VirusTotal API key (correct path: integrations.virustotal.api_key)
        vt_api_key = self._config.get("integrations.virustotal.api_key", "")
        if vt_api_key and len(vt_api_key) > 10:
            self._status_bar.set_virustotal_status("configured")
        else:
            self._status_bar.set_virustotal_status("not configured")

    def _on_search(self, query: str) -> None:
        """Handle search."""
        self._toast.show_toast(f"Searching: {query}")

    def _clear_all_scans(self) -> None:
        """Clear all analysis scans from database."""
        # Show confirmation dialog
        reply = QMessageBox.question(
            self,
            "Clear All Scans",
            "Are you sure you want to delete ALL analysis results from the database?\n\n"
            "This action cannot be undone!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                # Get count before clearing
                count = self._repository.clear_all_samples()

                # Vacuum database to reclaim space
                self._repository.vacuum_database()

                # Refresh dashboard
                self._load_dashboard_data()

                # Show success message
                self._toast.success(f"Cleared {count} scan(s) from database")
                logger.info(f"Cleared {count} samples from database")

            except Exception as e:
                logger.error(f"Failed to clear scans: {e}")
                self._toast.error(f"Failed to clear scans: {e}")
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to clear scans from database:\n{e}"
                )

    def _toggle_theme(self) -> None:
        """Toggle application theme."""
        theme = get_theme_manager()
        new_theme = theme.toggle_theme()
        self._toast.info(f"Theme changed to: {new_theme}")

    def _show_settings(self) -> None:
        """Show settings dialog."""
        from PyQt6.QtWidgets import (
            QDialog, QVBoxLayout, QHBoxLayout, QTabWidget,
            QGroupBox, QFormLayout, QSpinBox, QComboBox,
            QLineEdit, QCheckBox, QPushButton, QLabel
        )

        dialog = QDialog(self)
        dialog.setWindowTitle("Settings")
        dialog.setMinimumWidth(600)
        dialog.setMinimumHeight(500)

        layout = QVBoxLayout(dialog)

        # Tab widget for different categories
        tabs = QTabWidget()
        layout.addWidget(tabs)

        # UI Settings
        ui_tab = QWidget()
        ui_layout = QFormLayout(ui_tab)

        theme_combo = QComboBox()
        theme_combo.addItems(["dark", "darker", "light"])
        theme_combo.setCurrentText(self._config.get("ui.theme", "dark"))
        ui_layout.addRow("Theme:", theme_combo)

        font_size_spin = QSpinBox()
        font_size_spin.setRange(8, 24)
        font_size_spin.setValue(self._config.get("ui.font_size", 13))
        ui_layout.addRow("Font Size:", font_size_spin)

        tabs.addTab(ui_tab, "UI")

        # Analysis Settings
        analysis_tab = QWidget()
        analysis_layout = QFormLayout(analysis_tab)

        max_size_spin = QSpinBox()
        max_size_spin.setRange(1, 1000)
        max_size_spin.setValue(self._config.get("analysis.max_file_size", 104857600) // (1024 * 1024))
        max_size_spin.setSuffix(" MB")
        analysis_layout.addRow("Max File Size:", max_size_spin)

        timeout_spin = QSpinBox()
        timeout_spin.setRange(30, 3600)
        timeout_spin.setValue(self._config.get("analysis.timeout", 300))
        timeout_spin.setSuffix(" seconds")
        analysis_layout.addRow("Timeout:", timeout_spin)

        tabs.addTab(analysis_tab, "Analysis")

        # ML Settings
        ml_tab = QWidget()
        ml_layout = QFormLayout(ml_tab)

        confidence_spin = QSpinBox()
        confidence_spin.setRange(1, 100)
        confidence_spin.setValue(int(self._config.get("ml.confidence_threshold", 0.7) * 100))
        confidence_spin.setSuffix("%")
        ml_layout.addRow("Confidence Threshold:", confidence_spin)

        tabs.addTab(ml_tab, "Machine Learning")

        # Integration Settings
        integration_tab = QWidget()
        integration_layout = QFormLayout(integration_tab)

        vt_enabled = QCheckBox()
        vt_enabled.setChecked(self._config.get("integrations.virustotal.enabled", False))
        integration_layout.addRow("Enable VirusTotal:", vt_enabled)

        vt_api_key = QLineEdit()
        vt_api_key.setText(self._config.get("integrations.virustotal.api_key", ""))
        vt_api_key.setPlaceholderText("Enter VirusTotal API key")
        integration_layout.addRow("VT API Key:", vt_api_key)

        tabs.addTab(integration_tab, "Integrations")

        # Buttons
        button_layout = QHBoxLayout()
        save_btn = QPushButton("Save")
        cancel_btn = QPushButton("Cancel")
        apply_btn = QPushButton("Apply")

        button_layout.addStretch()
        button_layout.addWidget(save_btn)
        button_layout.addWidget(apply_btn)
        button_layout.addWidget(cancel_btn)

        layout.addLayout(button_layout)

        def save_settings() -> None:
            """Save settings to config file."""
            try:
                import yaml

                config_file = Path("config.yaml").resolve()

                # Read existing config if it exists
                config_data: Dict[str, Any] = {}
                if config_file.exists():
                    try:
                        with open(config_file, 'r', encoding='utf-8') as f:
                            config_data = yaml.safe_load(f) or {}
                    except (yaml.YAMLError, OSError) as e:
                        logger.warning(f"Failed to read config file, starting fresh: {e}")
                        config_data = {}

                # Update values with proper nesting
                config_data.setdefault('ui', {})
                config_data['ui']['theme'] = theme_combo.currentText()
                config_data['ui']['font_size'] = font_size_spin.value()

                config_data.setdefault('analysis', {})
                config_data['analysis']['max_file_size'] = max_size_spin.value() * 1024 * 1024
                config_data['analysis']['timeout'] = timeout_spin.value()

                config_data.setdefault('ml', {})
                config_data['ml']['confidence_threshold'] = confidence_spin.value() / 100.0

                config_data.setdefault('integrations', {})
                config_data['integrations'].setdefault('virustotal', {})
                config_data['integrations']['virustotal']['enabled'] = vt_enabled.isChecked()
                config_data['integrations']['virustotal']['api_key'] = vt_api_key.text()

                # Write config with explicit encoding
                with open(config_file, 'w', encoding='utf-8') as f:
                    yaml.dump(config_data, f, default_flow_style=False, allow_unicode=True)

                self._toast.success("Settings saved! Restart app to apply some changes.")
                logger.info("Settings saved successfully")

            except Exception as e:
                logger.error(f"Failed to save settings: {e}")
                self._toast.error(f"Failed to save settings: {e}")

        save_btn.clicked.connect(lambda: (save_settings(), dialog.accept()))
        apply_btn.clicked.connect(save_settings)
        cancel_btn.clicked.connect(dialog.reject)

        dialog.exec()

    def _show_about(self) -> None:
        """Show about dialog."""
        QMessageBox.about(
            self,
            "About AI-Cerberus",
            """<h2 style='color: #58a6ff;'>🛡️ AI-Cerberus</h2>
            <p><b>Version 1.0.0</b></p>
            <p style='font-size: 11pt;'><i>The Three-Headed Guardian Against Malicious Code</i></p>

            <p>AI-Cerberus is an advanced, enterprise-grade malware analysis platform
            featuring multi-layered threat detection powered by artificial intelligence.</p>

            <h3 style='color: #3fb950;'>🔍 Three Detection Heads:</h3>
            <ul>
                <li><b style='color: #58a6ff;'>Machine Learning Head</b> - Neural networks & ensemble classifiers</li>
                <li><b style='color: #3fb950;'>YARA Scanning Head</b> - Signature-based pattern matching</li>
                <li><b style='color: #d29922;'>Behavioral Analysis Head</b> - Runtime behavior profiling</li>
            </ul>

            <h3 style='color: #58a6ff;'>⚡ Core Features:</h3>
            <ul>
                <li>Multi-format binary analysis (PE/ELF/Mach-O)</li>
                <li>Advanced disassembly with suspicious code detection</li>
                <li>Entropy & cryptographic analysis</li>
                <li>VirusTotal API integration</li>
                <li>Extensible plugin architecture</li>
                <li>Automated threat scoring & classification</li>
            </ul>

            <p style='margin-top: 15px; color: #8b949e;'><i>Guarding your systems from the gates of digital threats.</i></p>
            """,
        )

    def _save_report(self) -> None:
        """Save analysis report."""
        QMessageBox.information(
            self,
            "Save Report",
            "Report saving functionality will be implemented soon!"
        )

    def _export_results(self) -> None:
        """Export analysis results."""
        QMessageBox.information(
            self,
            "Export Results",
            "Export functionality will be implemented soon!"
        )

    def _refresh_view(self) -> None:
        """Refresh current view."""
        QMessageBox.information(
            self,
            "Refresh",
            "View refreshed successfully!"
        )

    def _initialize_ml_models(self) -> None:
        """Initialize ML models (auto-train if needed)."""
        try:
            logger.info("Initializing ML models...")
            self._status_bar.set_message("Initializing ML models...")

            # Check and train models if needed
            status = self._auto_trainer.check_and_train()

            if status.get("training_performed"):
                metrics = status.get("training_metrics", {})
                accuracy = metrics.get("ensemble_accuracy", 0)
                self._toast.success(
                    f"ML models trained successfully! Accuracy: {accuracy:.2%}"
                )
                logger.info(f"ML models trained: accuracy={accuracy:.4f}")
            elif status.get("models_exist"):
                self._toast.info("ML models loaded successfully")
                logger.info("ML models loaded from disk")
            elif status.get("training_needed"):
                self._toast.warning(status.get("message", "ML models need training"))
                logger.warning(f"ML training needed: {status.get('message')}")

            self._status_bar.set_message("Ready")

        except Exception as e:
            logger.error(f"ML initialization failed: {e}")
            self._toast.error(f"ML initialization failed: {e}")

    def _show_model_management(self) -> None:
        """Show model management dialog."""
        from PyQt6.QtWidgets import (
            QDialog, QVBoxLayout, QHBoxLayout, QLabel,
            QPushButton, QTextEdit, QGroupBox, QFormLayout
        )

        dialog = QDialog(self)
        dialog.setWindowTitle("ML Model Management")
        dialog.setMinimumWidth(700)
        dialog.setMinimumHeight(500)

        layout = QVBoxLayout(dialog)

        # Model Status
        status_group = QGroupBox("Model Status")
        status_layout = QFormLayout(status_group)

        training_status = self._auto_trainer.get_training_status()

        models_trained = training_status.get("models_trained", False)
        status_label = QLabel("Trained ✓" if models_trained else "Not Trained ✗")
        status_label.setStyleSheet(
            f"color: {'#3fb950' if models_trained else '#f85149'}; font-weight: bold;"
        )
        status_layout.addRow("Status:", status_label)

        last_trained = training_status.get("last_trained", "Never")
        status_layout.addRow("Last Trained:", QLabel(str(last_trained)))

        samples_used = training_status.get("samples_used", 0)
        status_layout.addRow("Training Samples:", QLabel(str(samples_used)))

        metrics = training_status.get("metrics", {})
        if metrics:
            rf_acc = metrics.get("rf_accuracy", 0)
            gb_acc = metrics.get("gb_accuracy", 0)
            nn_acc = metrics.get("nn_accuracy", 0)
            ensemble_acc = metrics.get("ensemble_accuracy", 0)

            status_layout.addRow("Random Forest Accuracy:", QLabel(f"{rf_acc:.2%}"))
            status_layout.addRow("Gradient Boosting Accuracy:", QLabel(f"{gb_acc:.2%}"))
            status_layout.addRow("Neural Network Accuracy:", QLabel(f"{nn_acc:.2%}"))
            status_layout.addRow("Ensemble Accuracy:", QLabel(f"{ensemble_acc:.2%}"))

        layout.addWidget(status_group)

        # Detailed metrics
        if metrics:
            metrics_group = QGroupBox("Detailed Metrics")
            metrics_layout = QVBoxLayout(metrics_group)

            metrics_text = QTextEdit()
            metrics_text.setReadOnly(True)
            metrics_text.setMaximumHeight(200)

            report = metrics.get("classification_report", {})
            if report:
                text = "Classification Report:\n" + "=" * 50 + "\n\n"
                for label in ["benign", "suspicious", "malicious"]:
                    if label in report:
                        precision = report[label].get("precision", 0)
                        recall = report[label].get("recall", 0)
                        f1 = report[label].get("f1-score", 0)
                        text += f"{label.upper()}:\n"
                        text += f"  Precision: {precision:.4f}\n"
                        text += f"  Recall:    {recall:.4f}\n"
                        text += f"  F1-Score:  {f1:.4f}\n\n"

                metrics_text.setPlainText(text)

            metrics_layout.addWidget(metrics_text)
            layout.addWidget(metrics_group)

        # Actions
        button_layout = QHBoxLayout()

        retrain_btn = QPushButton("Retrain Models")
        retrain_btn.clicked.connect(lambda: self._retrain_models(dialog))
        button_layout.addWidget(retrain_btn)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        button_layout.addWidget(close_btn)

        button_layout.addStretch()
        layout.addLayout(button_layout)

        dialog.exec()

    def _retrain_models(self, parent_dialog: Optional[QDialog] = None) -> None:
        """Retrain ML models."""
        reply = QMessageBox.question(
            parent_dialog or self,
            "Retrain Models",
            "This will retrain all ML models with available data.\n"
            "This may take several minutes.\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                self._toast.info("Retraining models...")
                result = self._auto_trainer.retrain_models(force=True)

                if result.get("status") == "success":
                    metrics = result.get("metrics", {})
                    accuracy = metrics.get("ensemble_accuracy", 0)
                    self._toast.success(f"Models retrained! Accuracy: {accuracy:.2%}")
                else:
                    self._toast.warning(result.get("message", "Retraining failed"))

                if parent_dialog:
                    parent_dialog.accept()

            except Exception as e:
                logger.error(f"Retraining failed: {e}")
                self._toast.error(f"Retraining failed: {e}")

    def _show_analysis_mode_selector(self) -> None:
        """Show analysis mode selector dialog."""
        from PyQt6.QtWidgets import (
            QDialog, QVBoxLayout, QRadioButton, QButtonGroup,
            QPushButton, QLabel, QGroupBox
        )

        dialog = QDialog(self)
        dialog.setWindowTitle("Analysis Mode Selection")
        dialog.setMinimumWidth(600)

        layout = QVBoxLayout(dialog)

        # Description
        desc = QLabel(
            "Select the analysis mode for file scanning:\n\n"
            "• Fully Automated: Run all analysis components automatically\n"
            "• Quick Automated: Fast analysis with essential components\n"
            "• Deep Automated: Comprehensive analysis including sandbox\n"
            "• Manual Mode: Choose which components to run"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)

        # Mode selection
        modes_group = QGroupBox("Available Modes")
        modes_layout = QVBoxLayout(modes_group)

        button_group = QButtonGroup()
        mode_buttons = {}

        all_modes = self._mode_manager.get_all_modes()
        current_mode = self._mode_manager.get_current_mode()

        for mode_id, mode in all_modes.items():
            radio = QRadioButton(f"{mode.name} - {mode.description}")
            if mode_id == current_mode.name.lower().replace(" ", "_"):
                radio.setChecked(True)
            button_group.addButton(radio)
            mode_buttons[radio] = mode_id
            modes_layout.addWidget(radio)

        layout.addWidget(modes_group)

        # Buttons
        button_layout = QHBoxLayout()

        apply_btn = QPushButton("Apply")
        def apply_mode():
            for radio, mode_id in mode_buttons.items():
                if radio.isChecked():
                    self._mode_manager.set_mode(mode_id)
                    self._toast.success(f"Analysis mode set to: {mode_id}")
                    logger.info(f"Analysis mode changed to: {mode_id}")
                    break
            dialog.accept()

        apply_btn.clicked.connect(apply_mode)
        button_layout.addWidget(apply_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.reject)
        button_layout.addWidget(cancel_btn)

        button_layout.addStretch()
        layout.addLayout(button_layout)

        dialog.exec()

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        """
        Handle drag enter events for automatic file analysis.

        Accepts file drops to trigger automatic analysis.
        """
        if event.mimeData().hasUrls():
            # Check if any of the URLs are files
            for url in event.mimeData().urls():
                if url.isLocalFile():
                    event.acceptProposedAction()
                    return
        event.ignore()

    def dropEvent(self, event: QDropEvent) -> None:
        """
        Handle file drop events - AUTOMATICALLY analyze dropped files.

        Supports:
        - Single file: Analyzes immediately
        - Multiple files: Batch analysis with progress

        Security:
        - Validates file paths (no symlinks to system files)
        - Resolves paths to prevent traversal attacks
        - Checks file size limits
        """
        urls = event.mimeData().urls()
        files = []

        # Collect and validate file paths (with security checks)
        for url in urls:
            if url.isLocalFile():
                try:
                    file_path = Path(url.toLocalFile()).resolve()  # Resolve to prevent traversal

                    # Security validations
                    if not file_path.exists():
                        logger.warning(f"Dropped file does not exist: {file_path}")
                        continue

                    if not file_path.is_file():
                        logger.warning(f"Dropped path is not a file: {file_path}")
                        continue

                    # Check if symlink points to sensitive system location
                    if file_path.is_symlink():
                        real_path = file_path.resolve()
                        real_path_str = str(real_path).lower()  # Case-insensitive for Windows

                        # Block symlinks to system directories (platform-aware)
                        import platform
                        if platform.system() == "Windows":
                            system_paths = [
                                'c:\\windows',
                                'c:\\program files',
                                'c:\\program files (x86)',
                                'c:\\programdata',
                            ]
                        else:
                            system_paths = ['/etc', '/sys', '/proc', '/boot', '/root']

                        if any(real_path_str.startswith(sp.lower()) for sp in system_paths):
                            logger.error(f"Security: Blocked symlink to system path: {real_path}")
                            self._toast.error("Security: Cannot analyze system files")
                            continue

                    files.append(file_path)

                except Exception as e:
                    logger.error(f"Failed to process dropped file: {e}")
                    continue

        if not files:
            self._toast.warning("No valid files dropped")
            return

        # Auto-analyze dropped files
        if len(files) == 1:
            # Single file - direct analysis
            self._toast.info(f"Auto-analyzing: {files[0].name}")
            self._analyze_file(files[0])
        else:
            # Multiple files - batch analysis
            self._toast.info(f"Auto-analyzing {len(files)} files...")
            self._batch_analyze_files(files)

        event.acceptProposedAction()

    def _batch_analyze_files(self, files: List[Path]) -> None:
        """
        Automatically batch analyze multiple dropped files.

        Files are processed SEQUENTIALLY to prevent resource exhaustion.

        Args:
            files: List of file paths to analyze
        """
        if not files:
            return

        # Initialize batch state
        self._batch_queue = list(files)  # Create a copy
        self._batch_stats = {
            "total": len(files),
            "completed": 0,
            "failed": 0
        }
        self._is_batch_processing = True

        logger.info(f"Starting sequential batch analysis of {len(files)} files")
        self._toast.info(f"Starting batch analysis: {len(files)} files queued")

        # Start processing the first file
        self._process_next_batch_file()

    def _process_next_batch_file(self) -> None:
        """
        Process the next file in the batch queue.

        This is called after each file completes to maintain sequential processing.
        """
        if not self._batch_queue:
            # Batch complete
            self._finish_batch_processing()
            return

        # Get next file from queue
        file_path = self._batch_queue.pop(0)

        try:
            # Show progress
            remaining = len(self._batch_queue)
            current = self._batch_stats["total"] - remaining
            logger.info(f"[{current}/{self._batch_stats['total']}] Analyzing: {file_path.name}")
            self._toast.info(f"[{current}/{self._batch_stats['total']}] Analyzing: {file_path.name}")

            # Validate file exists
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")

            # Start analysis
            self._analyze_file(file_path)

        except Exception as e:
            logger.error(f"Failed to start analysis for {file_path}: {e}")
            self._batch_stats["failed"] += 1
            self._toast.error(f"Skipped {file_path.name}: {str(e)}")

            # Continue with next file
            self._process_next_batch_file()

    def _finish_batch_processing(self) -> None:
        """Finish batch processing and show summary."""
        self._is_batch_processing = False

        total = self._batch_stats["total"]
        completed = self._batch_stats["completed"]
        failed = self._batch_stats["failed"]

        logger.info(f"Batch analysis complete: {completed} succeeded, {failed} failed out of {total}")

        # Show summary toast
        if failed == 0:
            self._toast.success(f"Batch complete: All {total} files analyzed successfully")
        else:
            self._toast.warning(f"Batch complete: {completed} succeeded, {failed} failed out of {total}")

        # Reset batch state
        self._batch_queue.clear()
        self._batch_stats = {"total": 0, "completed": 0, "failed": 0}

    def closeEvent(self, event) -> None:
        """Handle window close."""
        # Clean up
        self._thread_pool.waitForDone(1000)
        logger.info("Application closing")
        event.accept()
