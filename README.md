# Antivirus

Antivirus Script

Overview

This Python script implements a basic antivirus system with real-time file system monitoring, process monitoring, registry monitoring, and a graphical user interface (GUI) for alerts. It uses the TLSH (Trend Micro Locality Sensitive Hash) library to detect potential malware by comparing file hashes against a database of known malware signatures from @VISWESWARAN1998 open-threat-database repository (https://github.com/VISWESWARAN1998/open-threat-database).

Features

File System Monitoring: Monitors a specified directory (default: user's Documents folder) for new files and checks them against malware signatures using TLSH.

Process Monitoring: Tracks running processes and flags those with high CPU usage as potentially suspicious.

Registry Monitoring: Watches for suspicious entries in the Windows registry under Software\Microsoft\Windows\CurrentVersion\Run.

Quarantine System: Moves detected malicious files to a quarantine directory and logs details in a SQLite database.

GUI Alerts: Displays real-time alerts for detected threats using a Tkinter-based interface.

Logging: Maintains detailed logs in antivirus.log for debugging and tracking.

Prerequisites
Python 3.7+
Required Libraries:
tlsh (for hash-based malware detection)
psutil (for process monitoring)
watchdog (for file system monitoring)
tkinter (for GUI alerts)
sqlite3 (included in Python standard library)
winreg (included in Python standard library, Windows only)
json, os, shutil, pathlib, threading, queue, logging, time
Windows OS: The registry monitoring feature is Windows-specific due to the use of winreg.

Install dependencies using:

pip install tlsh psutil watchdog


SETUP

Clone or Download the Script: Save the script to a directory of your choice.

Create a Signatures Directory: Place malware signature JSON files in a signatures directory or use the ones in the repository. Each JSON file should contain:

tlsh: The TLSH hash of the malware.
name: The name of the malware.
size (optional): The file size in bytes.
type (optional): The file type (e.g., application/x-msdownload for executables). Example:

{
    "tlsh": "T1A3B2...",
    "name": "example_malware",
    "size": 123456,
    "type": "application/x-msdownload"
}

Run the Script: Execute the script using Python:

python antivirus.py
Monitor Output: The script will:
Create a quarantine directory for detected files.
Initialize a quarantine.db SQLite database to log quarantined files.
Generate an antivirus.log file for detailed logging.
Display a Tkinter GUI window for real-time alerts.
Usage
The script monitors the user's Documents folder (~/Documents) by default for new files.

Suspicious files are quarantined, and alerts are shown in the GUI.

High-CPU processes (>80%) and suspicious registry entries are flagged and logged.

To stop the script, press Ctrl+C in the terminal.

Limitations and Future Improvements

False Positives: The current implementation may generate a significant number of false positives due to the simplicity of the TLSH similarity threshold and basic heuristic checks (e.g., CPU usage, registry keywords). This is a known limitation.

Future Work: Efforts are underway to enhance the detection logic to reduce false positives and improve accuracy, aiming to reach the effectiveness of industry-standard antivirus solutions like Microsoft Defender and Kaspersky. Planned improvements include:

Machine learning-based classification for better malware detection.

More sophisticated heuristic analysis.

Integration with external threat intelligence feeds.

Improved signature database management.

Platform Limitation: Registry monitoring is Windows-specific. Future versions may include cross-platform support.

Notes
Ensure the signatures directory contains valid JSON files with malware signatures for effective detection.

The script requires administrative privileges for certain operations (e.g., moving files to quarantine, accessing some processes).

Check antivirus.log for detailed error messages and debugging information if issues arise.

Disclaimer
This is a basic antivirus prototype and not a replacement for commercial antivirus software. Use it for educational purposes or as a starting point for custom security tools. The developer is not responsible for any damage caused by its use.

License

This project is licensed under the MIT License.
