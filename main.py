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

🚀 AUTOMATIC FEATURES:
- Drag-and-drop files → Auto-analyze
- Command-line args → Auto-analyze
- Batch processing → Auto-analyze multiple files
- Folder monitoring → Auto-analyze all files

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

import sys
import argparse
from pathlib import Path
from PyQt6.QtCore import QTimer

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))


def parse_arguments():
    """Parse command-line arguments."""
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

    return parser.parse_args()


def main():
    """Main application entry point."""
    from src.ui.app import create_application
    from src.ui.main_window import MainWindow
    from src.utils.logger import get_logger

    logger = get_logger("main")
    logger.info("Starting Malware Analysis Platform")

    # Parse arguments
    args = parse_arguments()

    try:
        # Create application
        app = create_application(sys.argv)

        # Create main window
        window = MainWindow()
        window.show()

        # AUTOMATIC ANALYSIS: Handle command line arguments
        files_to_analyze = []

        # Collect files from direct arguments
        if args.files:
            for file_arg in args.files:
                file_path = Path(file_arg)
                if file_path.exists() and file_path.is_file():
                    files_to_analyze.append(file_path)
                else:
                    logger.warning(f"File not found or invalid: {file_arg}")

        # Collect files from folder
        if args.folder:
            folder_path = Path(args.folder)
            if folder_path.exists() and folder_path.is_dir():
                pattern = "**/*" if args.recursive else "*"
                for file_path in folder_path.glob(pattern):
                    if file_path.is_file():
                        files_to_analyze.append(file_path)
                logger.info(f"Found {len(files_to_analyze)} files in folder: {args.folder}")
            else:
                logger.error(f"Folder not found: {args.folder}")

        # Auto-analyze collected files (with small delay to let UI load)
        if files_to_analyze:
            def auto_analyze():
                if len(files_to_analyze) == 1:
                    logger.info(f"Auto-analyzing file: {files_to_analyze[0]}")
                    window._analyze_file(files_to_analyze[0])
                else:
                    logger.info(f"Auto-analyzing {len(files_to_analyze)} files")
                    window._batch_analyze_files(files_to_analyze)

            # Trigger analysis after UI is fully loaded (500ms delay)
            QTimer.singleShot(500, auto_analyze)

        # Run application
        sys.exit(app.exec())

    except Exception as e:
        logger.critical(f"Application failed to start: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
