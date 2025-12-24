"""
Network Packet Investigator - Module Tests

Simple test script to verify all modules can be imported
and basic functionality works.

Run: python test_modules.py
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_imports():
    """Test that all modules can be imported."""
    print("Testing module imports...")
    
    try:
        from pcap_parser import PCAPParser
        print("✓ pcap_parser module imported successfully")
    except Exception as e:
        print(f"✗ Failed to import pcap_parser: {e}")
        return False
    
    try:
        from analyzer import NetworkAnalyzer
        print("✓ analyzer module imported successfully")
    except Exception as e:
        print(f"✗ Failed to import analyzer: {e}")
        return False
    
    try:
        from detector import ThreatDetector
        print("✓ detector module imported successfully")
    except Exception as e:
        print(f"✗ Failed to import detector: {e}")
        return False
    
    try:
        from reporter import ForensicReporter
        print("✓ reporter module imported successfully")
    except Exception as e:
        print(f"✗ Failed to import reporter: {e}")
        return False
    
    try:
        import gui
        print("✓ gui module imported successfully")
    except Exception as e:
        print(f"✗ Failed to import gui: {e}")
        return False
    
    return True


def test_dependencies():
    """Test that required dependencies are installed."""
    print("\nTesting dependencies...")
    
    dependencies = {
        'scapy': 'scapy.all',
        'matplotlib': 'matplotlib.pyplot',
        'tkinter': 'tkinter'
    }
    
    all_ok = True
    for name, module_path in dependencies.items():
        try:
            __import__(module_path)
            print(f"✓ {name} is installed")
        except ImportError as e:
            print(f"✗ {name} is NOT installed: {e}")
            all_ok = False
    
    return all_ok


def test_directory_structure():
    """Test that required directories exist."""
    print("\nTesting directory structure...")
    
    required_dirs = ['src', 'data', 'outputs', 'logs', 'docs']
    all_ok = True
    
    for dir_name in required_dirs:
        if os.path.isdir(dir_name):
            print(f"✓ Directory '{dir_name}' exists")
        else:
            print(f"✗ Directory '{dir_name}' is missing")
            all_ok = False
    
    return all_ok


def test_files():
    """Test that required files exist."""
    print("\nTesting required files...")
    
    required_files = [
        'main.py',
        'requirements.txt',
        'README.md',
        'data/safe_domains.txt',
        'src/__init__.py',
        'src/pcap_parser.py',
        'src/analyzer.py',
        'src/detector.py',
        'src/reporter.py',
        'src/gui.py'
    ]
    
    all_ok = True
    for file_path in required_files:
        if os.path.isfile(file_path):
            print(f"✓ File '{file_path}' exists")
        else:
            print(f"✗ File '{file_path}' is missing")
            all_ok = False
    
    return all_ok


def test_safe_domains():
    """Test that safe domains file is readable."""
    print("\nTesting safe domains configuration...")
    
    try:
        with open('data/safe_domains.txt', 'r') as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"✓ Safe domains file is readable ({len(domains)} domains loaded)")
            return True
    except Exception as e:
        print(f"✗ Failed to read safe domains: {e}")
        return False


def main():
    """Run all tests."""
    print("=" * 60)
    print("Network Packet Investigator - Module Tests")
    print("=" * 60)
    print()
    
    results = []
    
    results.append(("Directory Structure", test_directory_structure()))
    results.append(("Required Files", test_files()))
    results.append(("Dependencies", test_dependencies()))
    results.append(("Module Imports", test_imports()))
    results.append(("Safe Domains Config", test_safe_domains()))
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    all_passed = True
    for test_name, passed in results:
        status = "PASS" if passed else "FAIL"
        symbol = "✓" if passed else "✗"
        print(f"{symbol} {test_name}: {status}")
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✓ ALL TESTS PASSED")
        print("\nThe application is ready to use!")
        print("Run: python main.py")
    else:
        print("✗ SOME TESTS FAILED")
        print("\nPlease fix the issues above before running the application.")
        print("See README.md for installation instructions.")
    print("=" * 60)
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
