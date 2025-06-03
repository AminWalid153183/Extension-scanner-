# Extension-scanner-

🔐 Chrome Extension Security Scanner

This is a graduation project from Jordan University of Science and Technology (JUST). The system is designed to find and stop **malicious browser extensions** by using both static and dynamic analysis. It mixes JavaScript and WebAssembly analysis, YARA rules, and taint flow tracking, all wrapped up in a user-friendly web interface.

## 📚 Project Summary

As browser extensions get more popular, bad actors take advantage of them to sneak in, steal information, or do harmful things. Our system, **Extension to Detect Extensions (ETDE)**, helps users find and block suspicious extensions before they can cause any trouble.

## 🧠 Key Features

- ✅ **Static Analysis** using AST, Control Flow Graph (CFG), YARA Rules
- 🔄 **Dynamic Analysis** through OWASP ZAP API
- 🧪 **Taint Flow Detection** to follow harmful data paths
- 🧩 WebAssembly (WASM) binary checking
- 🔐 Connection with VirusTotal for threat information
- 📊 Risk scoring (Low, Medium, High)
- 🌐 Web frontend for real-time scanning
- 📦 SQLite database for keeping scan results

## 📁 Project Structure

📦project-root
┣ 📄 main.py ← FastAPI backend logic for scanning & analysis
┣ 📄 index.html ← Frontend interface for choosing scan level
┣ 📄 index.js ← JavaScript logic for running scans and showing results
┣ 📄 README.md ← This file
┗ 📄 extension_scans.db (made while running)

## 🚀 How to Run

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/extension-security-scanner.git
cd extension-security-scanner
```

### 2. Backend Setup
Install the necessary Python packages:

```bash
pip install -r requirements.txt
```

Create and set up the SQLite database:

```python
# Inside Python shell or at the top of main.py:
initialize_database()
```

Run the FastAPI server:

```bash
uvicorn main:app --reload
```

### 3. Frontend Setup
Just open index.html in your browser:

```bash
start index.html
```

Make sure the FastAPI server is running on http://localhost


project-root
┣ 📄 main.py ← FastAPI backend logic for scanning & analysis
┣ 📄 index.html ← Frontend interface for selecting scan level
┣ 📄 index.js ← JavaScript logic for scan execution and result rendering
┣ 📄 README.md ← This file
┗ 📄 extension_scans.db (created at runtime)
## 🚀 How to Run

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/extension-security-scanner.git
cd extension-security-scanner
```
Scan Levels
Low: Basic checks for permissions and metadata

Medium: Adds YARA patterns and analyzes JS structure

Aggressive: Covers complete taint flow, WASM, and sandboxing for API traffic

📊 Database Tables
scans: Sessions for scans

scan_results: Results for each extension


Team Members
Amin Walid Al-Tamimi (Team Leader)

Abed-Alrahman Ezzat Alzubidi

Mahdi Mohammad Jaradat

Ahed Youssef Shakhshir

Supervised by: Dr. Heba Alawneh



📄 License
This project is licensed for academic and educational use only.
