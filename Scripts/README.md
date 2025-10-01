# ⚙️ Automation Scripts (Bash, Python, etc.) 🐍

A collection of personal and work-related scripts designed to automate repetitive, administrative, and deployment tasks. Efficiency is key in DevOps, and these scripts demonstrate my ability to use **Bash** and **Python** to streamline workflows and reduce manual error.

---

## 📂 Categories of Scripts

| Folder | Purpose | Examples |
| :--- | :--- | :--- |
| **`bash-utilities`** | General-purpose shell scripts for Linux/Unix system tasks. | Log rotation, automated backups, file permission checks. |
| **`deployment-helpers`** | Scripts that wrap complex commands for easier application deployment. | Single-command Docker build/push, k8s context switching. |
| **`python-api`** | Scripts utilizing Python libraries for interacting with cloud APIs or reporting. | Simple AWS S3 inventory check, JSON data parsing. |

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

---

_These are my personal tools to make life easier. Hope you find them useful!_