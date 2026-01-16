#!/usr/bin/env python3
"""
Malware Analysis Platform - Main Entry Point

A professional, enterprise-grade malware analysis tool with:
- Modern PyQt6 dark theme interface
- Multi-format binary analysis (PE, ELF)
- ML-based classification (RF + GB + Neural Network)
- YARA rule scanning
- VirusTotal integration
- 100% AUTOMATIC analysis

AUTOMATIC FEATURES:
- Drag-and-drop files -> Auto-analyze
- Command-line args -> Auto-analyze
- Batch processing -> Auto-analyze multiple files
- Folder monitoring -> Auto-analyze all files

Usage:
    # Launch GUI (manual mode)
    python main.py

    # Auto-analyze single file
    python main.py malware.exe

    # Auto-analyze multiple files (batch)
    python main.py file1.exe file2.dll file3.sys

    # Auto-analyze entire folder
    python main.py --folder /path/to/samples

    # Auto-analyze folder recursively
    python main.py --folder /path/to/samples --recursive

    # In-app: Drag-and-drop files to auto-analyze!

Author: MalwareAnalyzer Team
License: MIT
"""

from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path
from typing import TYPE_CHECKING, List, NoReturn, Optional

# Add src to path (resolve to handle symlinks correctly)
sys.path.insert(0, str(Path(__file__).resolve().parent))

if TYPE_CHECKING:
    from src.ui.main_window import MainWindow
    from src.ui.app import MalwareAnalyzerApp

# Maximum number of files to process in batch mode to prevent resource exhaustion
MAX_BATCH_FILES = 1000


def check_dependencies() -> None:
    """
    Check that required dependencies are installed.

    Raises:
        SystemExit: If critical dependencies are missing.
    """
    missing_deps: List[str] = []

    try:
        import PyQt6  # noqa: F401
    except ImportError:
        missing_deps.append("PyQt6")

    try:
        import pefile  # noqa: F401
    except ImportError:
        missing_deps.append("pefile")

    if missing_deps:
        print("ERROR: Missing required dependencies:", file=sys.stderr)
        for dep in missing_deps:
            print(f"  - {dep}", file=sys.stderr)
        print("\nInstall missing dependencies with:", file=sys.stderr)
        print(f"  pip install {' '.join(missing_deps)}", file=sys.stderr)
        sys.exit(1)


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        description="Malware Analysis Platform - Enterprise-grade malware analysis",
        epilog="Examples:\n"
               "  python main.py malware.exe          # Analyze single file\n"
               "  python main.py file1.exe file2.dll  # Analyze multiple files\n"
               "  python main.py --folder /samples/   # Analyze all files in folder\n",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        'files',
        nargs='*',
        type=str,
        help='File(s) to analyze automatically'
    )

    parser.add_argument(
        '--folder', '-f',
        type=str,
        help='Folder containing files to analyze (batch mode)'
    )

    parser.add_argument(
        '--recursive', '-r',
        action='store_true',
        help='Recursively scan folder (use with --folder)'
    )

    parser.add_argument(
        '--max-files',
        type=int,
        default=MAX_BATCH_FILES,
        help=f'Maximum files to process in batch mode (default: {MAX_BATCH_FILES})'
    )

    parser.add_argument(
        '--log-level',
        type=str,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level (default: INFO)'
    )

    return parser.parse_args()


def collect_files_from_args(args: argparse.Namespace) -> List[Path]:
    """
    Collect files to analyze from command-line arguments.

    Args:
        args: Parsed command-line arguments.

    Returns:
        List of validated file paths to analyze.
    """
    from src.utils.logger import get_logger
    logger = get_logger("main")

    files_to_analyze: List[Path] = []

    # Collect files from direct arguments
    if args.files:
        for file_arg in args.files:
            try:
                # Resolve path for cross-platform compatibility and symlink handling
                file_path = Path(file_arg).resolve()
                if file_path.exists() and file_path.is_file():
                    files_to_analyze.append(file_path)
                else:
                    logger.warning(f"File not found or invalid: {file_arg}")
            except (OSError, ValueError) as e:
                logger.warning(f"Invalid path '{file_arg}': {e}")

    # Collect files from folder
    if args.folder:
        try:
            folder_path = Path(args.folder).resolve()
            if folder_path.exists() and folder_path.is_dir():
                pattern = "**/*" if args.recursive else "*"
                file_count = 0
                for file_path in folder_path.glob(pattern):
                    if file_path.is_file():
                        # Check file count limit
                        if file_count >= args.max_files:
                            logger.warning(
                                f"Reached maximum file limit ({args.max_files}). "
                                f"Use --max-files to increase."
                            )
                            break
                        files_to_analyze.append(file_path)
                        file_count += 1
                logger.info(f"Found {len(files_to_analyze)} files in folder: {args.folder}")
            else:
                logger.error(f"Folder not found: {args.folder}")
        except (OSError, ValueError) as e:
            logger.error(f"Invalid folder path '{args.folder}': {e}")

    return files_to_analyze


def setup_signal_handlers(app: Optional[MalwareAnalyzerApp] = None) -> None:
    """
    Set up signal handlers for graceful shutdown.

    Args:
        app: Optional QApplication instance for graceful quit.
    """
    def signal_handler(signum: int, frame: object) -> None:
        """Handle shutdown signals."""
        from src.utils.logger import get_logger
        logger = get_logger("main")

        signal_name = signal.Signals(signum).name
        logger.info(f"Received {signal_name}, shutting down gracefully...")

        if app is not None:
            app.quit()
        else:
            sys.exit(0)

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # On Windows, also handle SIGBREAK if available
    if hasattr(signal, 'SIGBREAK'):
        signal.signal(signal.SIGBREAK, signal_handler)


def main() -> NoReturn:
    """Main application entry point."""
    # Check dependencies before importing anything that depends on them
    check_dependencies()

    # Parse arguments early (before Qt initialization on some systems)
    args = parse_arguments()

    # Initialize logging system before use
    from src.utils.logger import setup_logging, get_logger
    setup_logging(level=args.log_level)

    logger = get_logger("main")
    logger.info("Starting Malware Analysis Platform")

    # Import Qt-dependent modules after dependency check
    from PyQt6.QtCore import QTimer
    from src.ui.app import create_application
    from src.ui.main_window import MainWindow

    try:
        # Set up signal handlers before creating application
        setup_signal_handlers()

        # Create application
        app = create_application(sys.argv)

        # Update signal handlers with app reference for graceful Qt quit
        setup_signal_handlers(app)

        # Create main window
        window = MainWindow()
        window.show()

        # Collect files to analyze from command line
        files_to_analyze = collect_files_from_args(args)

        # Auto-analyze collected files (with small delay to let UI load)
        if files_to_analyze:
            def auto_analyze() -> None:
                """Trigger automatic analysis of collected files."""
                try:
                    if len(files_to_analyze) == 1:
                        logger.info(f"Auto-analyzing file: {files_to_analyze[0]}")
                        window._analyze_file(files_to_analyze[0])
                    else:
                        logger.info(f"Auto-analyzing {len(files_to_analyze)} files")
                        window._batch_analyze_files(files_to_analyze)
                except Exception as e:
                    logger.error(f"Auto-analysis failed: {e}")

            # Trigger analysis after UI is fully loaded (500ms delay)
            QTimer.singleShot(500, auto_analyze)

        # Run application
        sys.exit(app.exec())

    except Exception as e:
        logger.critical(f"Application failed to start: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
