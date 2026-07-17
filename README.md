# File Cleaner & Malware Scanner

A professional Python tool that cleans directories by removing empty files and scanning the remaining files against the VirusTotal database using SHA-256 hashes.

## Features

-  Scan any directory recursively
-  Detect and remove empty files
-  Generate SHA-256 hashes for all remaining files
-  Check file hashes against the VirusTotal database
-  Display scan results in a clear and readable format
-  Fast and lightweight

---

## Project Structure


.
├── nettoyeur.py 
└── README.md
```

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/file-cleaner-malware-scanner.git
cd file-cleaner-malware-scanner
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

---

## VirusTotal API Key

Create a free VirusTotal account and generate an API key.

 https://www.virustotal.com/gui/join-us

---

## Usage

```bash
python nettoyeur.py /path/to/folder --api-key YOUR_API_KEY
```

### Example

```bash
python nettoyeur.py C:\Users\Aymane\Downloads --api-key xxxxxxxxxxxxxxxxxxxxxxxxx
```

---

## How It Works

The program performs the following steps:

1. Scans the selected directory recursively.
2. Detects empty files.
3. Deletes empty files automatically.
4. Computes the SHA-256 hash of every remaining file.
5. Queries the VirusTotal API using each hash.
6. Reports whether the file is known as malicious or clean.

---

## Requirements

- Python 3.10+
- Internet connection
- VirusTotal API Key

---

## Security Notice

This tool **does not upload files** to VirusTotal.

Only the **SHA-256 hash** of each file is sent, preserving file privacy while checking whether the file is already known by VirusTotal.

---

## Example Output

```
Scanning folder...

✔ Empty file removed:
    notes.txt

Scanning remaining files...

✔ report.pdf ............ Clean
✔ image.png ............. Clean
⚠ malware.exe ........... Malicious (12 detections)

Scan completed.
```
