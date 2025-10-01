# ⚙️ Automation Scripts 🐍

my little collection of scripts that are quite common in the system admin or devop world.

---

## 📁 Scripts Overview 
**1. File Organizer (fileorganizer.py)**
Automatically organizes files into categorized folders based on file type and optionally by date.
**2. Server Health Monitor (servermonitor.py)**
Monitors multiple servers with ping, port, and HTTP checks, with optional email alerts.
**3. Log Parser & Analyzer (logparser.py)**
Parses, analyzes, and generates reports from various log file formats with anomaly detection.

MORE TO COME!
---

## 🎯 Skill Highlights

* **Shell Proficiency:** Effective use of loops, conditionals, piping, and standard Linux utilities (`awk`, `sed`, `grep`).
* **Idempotency (Where applicable):** Writing scripts that can be run multiple times without causing unintended side effects.
* **Error Handling:** Using `set -e`, proper exit codes, and explicit logging to make scripts robust.
* **API Interaction:** Utilizing modern languages (like Python) to perform more complex, stateful operations.

---

## 📝 Tips for Using Scripts

1.  **Read Before Running:** Always examine a script's content, especially those that use `sudo` or modify system files.
2.  **Set Permissions:** Ensure the script has executable permissions: `chmod +x script_name.sh`.
3.  **Test in a Safe Environment:** Use a local or non-production environment for testing new scripts.

**Install all dependencies:**
pip install watchdog requests
or
pip install requests -> fileorganizer.py
pip install watchdog -> servermonitor.py


---
## 🚀 The End

Keep in mind, each script can be;
- Ran standalone from command line
- Scheduled with cron jobs
- Integrated into larger systems
- Extended with custom functionality
Hope this is somewhat useful to you.