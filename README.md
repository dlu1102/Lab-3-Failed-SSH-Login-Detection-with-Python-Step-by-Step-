# Home Lab Project #3 – Failed SSH Login Detection with Python

## 📌 Objective
Use Python to parse authentication logs and detect brute-force login attempts.  
This lab focused on troubleshooting real coding challenges (file paths, parsing mistakes) while building a script that SOC analysts could use to quickly identify failed SSH logins and attacker IPs.

---

## 🛠 Skills Practiced
- Python scripting for log parsing
- Handling Windows/Linux file paths safely
- Regex and string parsing logic
- Failed vs. successful login detection
- Unique attacker IP extraction
- Troubleshooting with AI assistance
- SOC mindset: thinking in terms of detection logic

---

## 🔍 Workflow

1. **Simulated Log File**
   1. Open Notepad (or any text editor)
   2. Paste the lines below exactly as shown
   3. Save the file as fake_log_python.txt (in downloads folder)
  
- Jan 14 10:15:32 kali sshd[12345]: Failed password for invalid user admin from 192.168.1.10 port 53422 ssh2
- Jan 14 10:15:35 kali sshd[12345]: Failed password for invalid user guest from 192.168.1.11 port 53425 ssh2
- Jan 14 10:15:40 kali sshd[12345]: Accepted password for valid user test from 192.168.1.12 port 53430 ssh2
- Jan 14 10:16:05 kali sshd[12345]: Failed password for invalid user admin from 192.168.1.10 port 53478 ssh2
- Jan 14 10:16:19 kali sshd[12345]: Failed password for invalid user root from 192.168.1.13 port 53491 ssh2
- Jan 14 10:16:33 kali sshd[12345]: Failed password for invalid user admin from 192.168.1.10 port 53504 ssh2
- Jan 14 10:16:49 kali sshd[12345]: Failed password for invalid user guest from 192.168.1.11 port 53520 ssh2
- Jan 14 10:17:02 kali sshd[12345]: Failed password for invalid user demo from 192.168.1.14 port 53533 ssh2
- Jan 14 10:17:15 kali sshd[12345]: Failed password for invalid user admin from 192.168.1.10 port 53546 ssh2
- Jan 14 10:17:27 kali sshd[12345]: Accepted password for valid user test from 192.168.1.12 port 53558 ssh2
- Jan 14 10:17:40 kali sshd[12345]: Failed password for invalid user root from 192.168.1.13 port 53571 ssh2
- Jan 14 10:17:55 kali sshd[12345]: Failed password for invalid user admin from 192.168.1.20 port 53586 ssh2

  This file has 10 failed and 2 successful logins across several IPs.

2. **Create the Python script**
   1. Open Python and paste the script below exactly as shown
   2. Press Enter/run the script
   3. When prompted, drag the fake_log_python.txt file into Python from the downloads folder and press Enter.
  
## 🐍 Python Script

```python
# parse_ssh_log.py
# Detect failed vs successful SSH logins and list attacker IPs

import re
from collections import Counter

# Prompt supports drag-and-drop of the log file in Windows terminal/PowerShell
path_raw = input("👉 Drag your log file here and press Enter: ").strip().strip('"').strip("'")
# Normalize Windows backslashes to forward slashes so Python doesn't choke on \U or \n
log_path = path_raw.replace("\\", "/")

failed_count = 0
success_count = 0
failed_ips = []
success_ips = []

# Regex patterns to capture IPs after 'from '
re_failed = re.compile(r'Failed password .* from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b', re.IGNORECASE)
re_success = re.compile(r'Accepted password .* from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b', re.IGNORECASE)

try:
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if m := re_failed.search(line):
                failed_count += 1
                failed_ips.append(m.group("ip"))
            elif m := re_success.search(line):
                success_count += 1
                success_ips.append(m.group("ip"))
except FileNotFoundError:
    print("❌ Could not open the file. Check the path and try again.")
    raise

unique_failed_ips = sorted(set(failed_ips))
top_failed = Counter(failed_ips).most_common(5)

print(f"🔐 Failed logins: {failed_count}")
print(f"✅ Successful logins: {success_count}")
print(f"🌍 Unique attacker IPs: {unique_failed_ips}")
print(f"🥇 Top sources (IP, attempts): {top_failed}")
```
4. **Expected Output** (with the sample fake_log_python.txt file from step 1)
     You should see this:
    - 🔐 Failed logins: 10
    - ✅ Successful logins: 2
    - 🌍 Unique attacker IPs: ['192.168.1.10', '192.168.1.11', '192.168.1.13', '192.168.1.14', '192.168.1.20']
    - 🥇 Top sources (IP, attempts): [('192.168.1.10', 4), ('192.168.1.11', 2), ('192.168.1.13', 2), ('192.168.1.14', 1), ('192.168.1.20', 1)]
    - Screenshot **<img width="1920" height="1080" alt="lab 3 python output" src="https://github.com/user-attachments/assets/bcc8d907-3730-4d5e-92aa-2788569f4c9e" />**


5. **Lessons Learned**
    - Troubleshooting builds transferable skills – Path errors, regex mistakes, and parsing logic all mirrored real-world SOC analyst challenges where logs don’t behave as expected.
    - Detection logic > tools – It’s not just about running Splunk or Python, but about knowing what patterns (failed vs. successful logins, repeated IPs) signal brute-force attempts.
    - Platform-agnostic thinking – By normalizing file paths and using regex, I built a script that works across Windows and Linux, reflecting cloud/multi-platform environments.
    - AI as a productivity booster – Using AI accelerated debugging but didn’t replace critical thinking; it kept me focused on the detection outcome, not stuck in syntax errors.
    - Confidence in entry-level workflows – After this project, I can reliably parse logs, extract attacker IPs, and generate detection insights — the same workflow expected in SOC internships and entry-level cloud security roles.

   

