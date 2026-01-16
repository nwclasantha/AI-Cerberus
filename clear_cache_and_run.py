"""Clear Python cache and run the application."""
import os
import sys
import shutil
from pathlib import Path

def clear_cache():
    """Remove all Python cache files and directories."""
    print("Clearing Python cache...")

    # Get the root directory
    root = Path(__file__).parent

    # Remove __pycache__ directories
    cache_dirs = list(root.rglob("__pycache__"))
    for cache_dir in cache_dirs:
        try:
            shutil.rmtree(cache_dir)
            print(f"Removed: {cache_dir}")
        except Exception as e:
            print(f"Error removing {cache_dir}: {e}")

    # Remove .pyc files
    pyc_files = list(root.rglob("*.pyc"))
    for pyc_file in pyc_files:
        try:
            pyc_file.unlink()
            print(f"Removed: {pyc_file}")
        except Exception as e:
            print(f"Error removing {pyc_file}: {e}")

    print(f"\nRemoved {len(cache_dirs)} cache directories and {len(pyc_files)} .pyc files")
    print("Cache cleared successfully!\n")

def verify_fixes():
    """Verify that the toast fixes are in place."""
    print("Verifying fixes in main_window.py...")

    main_window_path = Path(__file__).parent / "src" / "ui" / "main_window.py"

    with open(main_window_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Check for show_toast (correct)
    toast_count = content.count('self._toast.show_toast(')

    # Check for show_info (incorrect - should be 0)
    info_count = content.count('self._toast.show_info(')

    print(f"  - show_toast() calls: {toast_count} [OK]")
    print(f"  - show_info() calls: {info_count} {'[ERROR - SHOULD BE 0!]' if info_count > 0 else '[OK]'}")

    if info_count > 0:
        print("\n[WARNING] Old buggy code detected (show_info)!")
        print("The fixes may not have been saved properly.")
        return False

    print("\n[SUCCESS] All fixes verified in source code!\n")
    return True

def run_app():
    """Run the application without bytecode."""
    print("Starting application without bytecode cache...")
    print("=" * 60)

    # Import and run main
    sys.dont_write_bytecode = True  # Prevent .pyc creation

    import main
    # The main module will start the application

if __name__ == "__main__":
    print("=" * 60)
    print("MALWARE ANALYZER - CACHE CLEANER & LAUNCHER")
    print("=" * 60)
    print()

    # Step 1: Clear cache
    clear_cache()

    # Step 2: Verify fixes
    if not verify_fixes():
        print("\n⚠️  Please check that the source files have been saved correctly.")
        sys.exit(1)

    # Step 3: Run app
    run_app()
