"""
Network Packet Investigator - Main Entry Point

Description:
    Main entry point for the Network Packet Investigator forensic tool.
    Launches the GUI application for cross-platform network forensics analysis.

Author: Digital Forensics Team
Date: December 23, 2025
"""

import sys
import os
import logging

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from gui import main as run_gui


def setup_environment():
    """Setup the application environment."""
    # Create necessary directories
    directories = ['data', 'logs']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    # Setup logging
    log_file = os.path.join('logs', 'forensic_analysis.log')
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    logger = logging.getLogger(__name__)
    logger.info("=" * 80)
    logger.info("Network Packet Investigator - Digital Forensics Tool")
    logger.info("=" * 80)
    logger.info("Application starting...")


def main():
    """Main entry point."""
    try:
        setup_environment()
        run_gui()
    except Exception as e:
        logging.error(f"Application error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
