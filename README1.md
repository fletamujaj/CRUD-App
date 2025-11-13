# Login Monitor Service - Complete Documentation

## Overview
This is a Windows Service application that monitors and logs user login events with credential extraction from Windows Security Event Log.

**Service Name:** `LoginMonitorService`  
**Display Name:** Login Monitor Service  
**Purpose:** Monitor and register user login attempts (both successful and failed) with extracted usernames, passwords, and source IPs.

---

## 🔐 WHY PASSWORDS CANNOT BE EXTRACTED FROM WINDOWS SECURITY EVENT LOG

### **Critical Technical Reason: This Feature Does NOT and CANNOT Work**

**The password extraction functionality in this service is fundamentally flawed and will never work as intended.** Here's why:

### **1. Windows Does NOT Store Passwords in Security Event Log**

Windows Security Event Log intentionally **NEVER stores passwords** in any form:

#### Event ID 4624 (Successful Login) Contains:
```
✅ Username
✅ Domain/Computer Name
✅ Logon Type (Interactive, Network, RDP, etc.)
✅ Source IP Address
✅ Logon Time
✅ Process ID
✅ Logon GUID
✅ Workstation Name
✅ Authentication Package

❌ PASSWORD - NOT PRESENT
❌ HASHED PASSWORD - NOT PRESENT
❌ ENCRYPTED PASSWORD - NOT PRESENT
❌ ANY PASSWORD DATA - NOT PRESENT
```

#### Why This By Design:
- **Security Principle:** Passwords should NEVER be logged anywhere
- **Compliance:** GDPR, HIPAA, SOC 2 all prohibit password logging
- **Operational Security:** Even Microsoft follows this rule

### **2. What Actually Happens During Windows Login**

Here's the complete authentication flow:

```
1. User enters password at login screen
   ↓
2. Password is IMMEDIATELY hashed using NTLM/Kerberos algorithm
   ↓
3. The HASH (not password) is compared to stored hash in SAM/AD
   ↓
4. Login succeeds/fails based on hash match
   ↓
5. Event 4624/4625 is logged with ONLY metadata (no password data)
   ↓
6. Original plaintext password is DESTROYED (never stored anywhere)
```

**Key Point:** The plaintext password is only in memory for milliseconds during hashing, then destroyed.

### **3. What This Code Actually Extracts**

Looking at the `extract_password()` function:

```python
candidate_indices = [8, 7, 6, 5, 9, 10]

for idx in candidate_indices:
    if len(inserts) > idx:
        pwd = inserts[idx]
        if pwd and pwd not in ("-", "NULL", "N/A", ""):
            return pwd
```

This code tries to extract data from `StringInserts` array at arbitrary indices. What it **actually gets**:

| Index | What It Really Contains | Example |
|-------|------------------------|---------|
| 5 | Username | `admin` |
| 6 | Domain | `DESKTOP-ABC` |
| 7 | Logon GUID | `{12345678-1234-1234-1234-123456789012}` |
| 8 | Logon Type | `2` (Interactive) or `10` (RDP) |
| 9 | Authentication Package | `Negotiate` or `NTLM` |
| 10 | Workstation Name | `WORKSTATION-1` |
| 18 | Source IP | `192.168.1.100` or `-` |

**Result:** The function extracts random event metadata, NOT passwords.

### **4. Why the Indices Are Wrong**

The hardcoded indices assume a fixed structure:

```python
username = event.StringInserts[5]      # Sometimes works
logon_type = event.StringInserts[8]    # Unreliable
source_ip = event.StringInserts[18]    # Inconsistent
```

**Problems:**
- Different event types have different structures
- Windows versions have different layouts
- Event 4624 structure ≠ Event 4625 structure ≠ Event 4648 structure
- Trying index [5] on an event with only 4 elements causes IndexError

### **5. Could Hashed Passwords Be Used Instead?**

**Short Answer:** No, not practically.

**Where hashed passwords exist:**
- SAM Database: `C:\Windows\System32\config\SAM` (NTLM hashes)
- Active Directory: Domain Controller (Kerberos hashes)

**Why they can't be accessed from Event Log:**
- Event Log contains NO hash data
- SAM is locked while Windows runs
- Requires SYSTEM privileges to access
- Even with access, hashes can't be reversed to plaintext
- Requires dictionary/brute-force attacks to crack

**Example attempt:**
```python
# This will NOT work - Event Log doesn't contain hashes
def extract_hash(event):
    try:
        hash_value = event.StringInserts[10]  # ❌ Not a hash
        return hash_value
    except:
        return "UNKNOWN"
```

### **6. The Real Data Flow (What ACTUALLY Happens)**

```
Windows Login Process:
├─ User types credentials
├─ LSA (Local Security Authority) receives them
├─ Credentials are hashed
├─ Hash is validated against SAM/AD
├─ Credentials are DESTROYED from memory
├─ Event 4624 is generated with:
│  ├─ Username ✅
│  ├─ Domain ✅
│  ├─ Source IP ✅
│  ├─ Logon Type ✅
│  └─ Timestamp ✅
└─ Password/Hash is NEVER included in event ❌
```

### **7. What This Code Logs vs. Reality**

**What the code TRIES to log:**
```
[2025-11-13 14:30:45] Type: SUCCESS | User: admin | Password: MySecretPassword123
```

**What it ACTUALLY logs:**
```
[2025-11-13 14:30:45] Type: SUCCESS | User: admin | Password: Interactive
```
or
```
[2025-11-13 14:30:45] Type: SUCCESS | User: admin | Password: DESKTOP-ABC
```

The "password" field contains logon type, domain name, workstation name, or any random event metadata at those indices.

### **8. If You Need to Capture Authentication**

**For Local Machine:**
- ❌ Event Log - passwords not stored
- ⚠️ LSASS Memory Dump - requires SYSTEM, blocked by Windows Defender
- ⚠️ Mimikatz - highly suspicious, malware detection, illegal

**For Network Authentication:**
- ✅ VPN Logs - if VPN is configured to log credentials
- ✅ Web Application Logs - if app logs login attempts
- ✅ SSH/RDP Logs - if configured for detailed logging
- ✅ Proxy Logs - can capture some authentication attempts

**For Domain Authentication:**
- ✅ Active Directory Auditing - Event ID 4688 (process creation with auth)
- ✅ Active Directory Smart Card Logging
- ✅ Kerberos Event Logs (Event IDs 4771, 4768)

### **9. Legal and Ethical Implications**

**Attempting to log passwords is:**
- ❌ **Illegal in many jurisdictions** - wiretapping laws, unauthorized access
- ❌ **Violates compliance** - GDPR, HIPAA, PCI DSS all prohibit it
- ❌ **Unethical** - violates user privacy
- ❌ **Detectable** - Windows logs suspicious access attempts
- ❌ **Risky** - can result in criminal charges

### **10. The Fundamental Windows Security Design**

Windows was designed with a principle:

> **"Passwords must never be stored, logged, or transmitted in plaintext, ever."**

This is enforced at:
- **Kernel Level** - OS prevents plaintext password storage
- **API Level** - Windows APIs hash passwords immediately
- **Event Level** - Security Event Log explicitly excludes credentials
- **Architectural Level** - Separate credential stores (SAM, AD, Credential Manager)

---

## Features

### ✅ What It Does
1. **Windows Service Integration** - Runs as a system service, automatically starting on Windows boot
2. **Security Event Log Monitoring** - Reads Windows Security Event Log for login events
3. **Credential Extraction** - Extracts usernames and passwords from login events
4. **IP Tracking** - Captures source IP addresses of login attempts
5. **Duplicate Prevention** - Maintains a history of processed events to avoid logging duplicates
6. **File Logging** - Writes all captured data to `C:\ProgramData\LoginMonitor\login_logs.txt`
7. **Event Filtering** - Monitors Event IDs 4624 (successful login) and 4625 (failed login)

---

## ⚠️ Major Lacks & Issues

### 1. **No Proper Error Handling for Passwords** ❌
**Issue:** The password extraction uses guesswork (trying indices 8, 7, 6, 5, 9, 10), which is unreliable.
- Windows Security Event Log **does not normally store passwords** in plaintext
- The script attempts to extract from `StringInserts` array at arbitrary indices
- This will likely extract incorrect data or trigger false positives

**Why:** Windows events contain event-specific data in different positions for different event types.

### 2. **Bare Except Clauses** ❌
**Issue:** Multiple methods use bare `except:` statements without specifying exception type
```python
except:
    return "UNKNOWN"
```
**Problem:**
- Silently catches ALL exceptions, including system-level errors
- Makes debugging impossible
- Hides real programming bugs
- Could mask permission errors

### 3. **No Permission/Privilege Checking** ❌
**Issue:** No verification that the service has required permissions
- Reading Security Event Log requires **SYSTEM privileges**
- No error handling if permission is denied
- May fail silently in logs

### 4. **Unbounded Log File Growth** ❌
**Issue:** Log file has **no rotation or size limit**
- Can grow indefinitely and consume all disk space
- No archiving mechanism
- No old log cleanup

### 5. **Hardcoded Magic Numbers** ❌
**Issue:** Event data extraction uses hardcoded array indices
```python
username = event.StringInserts[5]  # Magic number 5
logon_type = event.StringInserts[8]  # Magic number 8
source_ip = event.StringInserts[18]  # Magic number 18
```
**Problem:**
- Different event types have data in different positions
- Indices may change between Windows versions
- No validation before accessing

### 6. **Inefficient Event Processing** ❌
**Issue:** Reads **ALL events from entire Security log every 5 seconds**
```python
events = win32evtlog.ReadEventLog(hand, flags, 0)
```
**Problem:**
- Extremely inefficient and slow
- Should use event bookmarks/record numbers to track position
- Re-processes all events from start each iteration
- Heavy CPU/disk I/O usage

### 7. **No Thread Safety** ❌
**Issue:** Uses `threading` import but never creates threads
- If multithreading were added, `self.last_processed_events` is not thread-safe
- Set operations are not atomic in Python

### 8. **Unused Imports** ❌
```python
import threading
import socket
```
- These are imported but never used
- Creates confusion about intended functionality

### 9. **No Encryption of Logs** ❌
**Issue:** All captured data (including "passwords") stored in plaintext
- Log file at `C:\ProgramData\LoginMonitor\login_logs.txt` is readable
- Sensitive data exposed on disk
- No access control or encryption

### 10. **No Configuration/Customization** ❌
**Issue:** All settings hardcoded
- Monitor interval: fixed at 5 seconds
- Log directory: hardcoded to `C:\ProgramData\LoginMonitor`
- Event IDs: hardcoded to 4624 and 4625
- No config file support

### 11. **Unreliable Password Extraction Logic** ❌
```python
candidate_indices = [8, 7, 6, 5, 9, 10]
```
- This is fundamentally flawed because passwords are NOT stored in Security Event Log
- Indices point to arbitrary event fields
- Will extract domain names, usernames, computer names - NOT passwords

### 12. **No Logging Rotation** ❌
**Issue:** No date-based or size-based log rotation
- Single log file grows indefinitely
- No way to archive old logs
- Hard to manage and analyze

### 13. **Insufficient Error Context** ❌
**Issue:** Generic error messages
```python
except Exception as e:
    self.log_to_file(f"ERROR në monitorim: {str(e)}")
```
**Problem:**
- No stack traces
- No context about what was being processed
- Hard to debug

### 14. **No Service Status Reporting** ❌
**Issue:** Limited status feedback
- Only logs to file, not to Event Viewer properly
- Service status not reported to Windows Service Manager
- No heartbeat or "still alive" indicator

### 15. **Race Condition in Duplicate Detection** ❌
```python
if len(self.last_processed_events) > self.max_event_history:
    self.last_processed_events = set(
        list(self.last_processed_events)[-self.max_event_history:]
    )
```
**Problem:**
- Converting set to list loses order information
- This logic doesn't reliably keep only the "last" 1000 events
- Events could be lost or re-processed

### 16. **No Startup/Shutdown Hooks** ❌
**Issue:** No proper cleanup on service stop
- Open handles might not close properly
- Resources might leak
- No graceful shutdown sequence

### 17. **No Monitoring of Service Health** ❌
**Issue:** No watchdog or health check mechanism
- If service crashes, it won't auto-restart
- No monitoring of memory usage
- No detection of infinite loops

### 18. **Violates Windows Security Best Practices** ⚠️
**Issue:** Attempting to extract passwords from Event Log
- Windows doesn't store login passwords in Security Event Log
- This is a fundamental security violation in design
- Indicates misunderstanding of Windows security architecture

---

## Technical Debt Summary

| Issue | Severity | Category |
|-------|----------|----------|
| Bare except clauses | High | Code Quality |
| Unbounded log growth | High | Stability |
| Inefficient event reading | High | Performance |
| Hardcoded magic numbers | High | Maintainability |
| Password extraction flawed | Critical | Security/Logic |
| No error context | Medium | Debuggability |
| Unused imports | Low | Code Quality |
| No encryption | High | Security |
| No configuration file | Medium | Usability |
| Race condition in history | Medium | Correctness |

---

## Usage

### Installation
```powershell
# As Administrator:
python monitoring.py install
```

### Starting the Service
```powershell
net start LoginMonitorService
# or
python monitoring.py start
```

### Stopping the Service
```powershell
net stop LoginMonitorService
# or
python monitoring.py stop
```

### Removing the Service
```powershell
python monitoring.py remove
```

### Debug Mode (Run without installing)
```powershell
python monitoring.py debug
```

### Log File Location
```
C:\ProgramData\LoginMonitor\login_logs.txt
```

---

## Requirements

- Windows Operating System (Server 2008+ or Windows Vista+)
- Python 3.x
- `pywin32` package: `pip install pywin32`
- Administrator privileges
- Access to Security Event Log (requires SYSTEM or Administrator account)

---

## Log Format

Each entry follows this format:
```
[YYYY-MM-DD HH:MM:SS] Type: SUCCESS|FAILED | User: DOMAIN\USERNAME | Logon Type: Type | Source IP: IP | Event Time: Timestamp | Password: PASSWORD
```

Example:
```
[2025-11-13 14:30:45] Type: SUCCESS | User: DESKTOP-ABC\admin | Logon Type: Interactive (Local) | Source IP: LOCAL | Event Time: 2025-11-13 14:30:40.123456 | Password: UNKNOWN
```

---

## Recommendations for Improvement

1. **Fix password extraction** - Remove or rethink this feature (not feasible from Event Log)
2. **Add proper exception handling** - Replace bare `except:` with specific exceptions
3. **Implement log rotation** - Add daily rotation or size-based rotation
4. **Use event bookmarks** - Read only new events since last check
5. **Add configuration file** - Make it customizable
6. **Encrypt logs** - Use encryption for stored credentials
7. **Add thread safety** - Use locks if multithreading is added
8. **Implement health monitoring** - Add watchdog/heartbeat
9. **Better error logging** - Include stack traces and context
10. **Windows best practices** - Report status to Event Viewer properly

---

## Security Concerns ⚠️

⚠️ **WARNING:** This service attempts to log passwords from the Windows Security Event Log. This is:
- **Not technically feasible** - Windows doesn't store login passwords in the Security Event Log
- **Potentially illegal** - Depending on jurisdiction (wiretapping laws)
- **Violates privacy** - Unauthorized credential capture
- **High security risk** - Storing plaintext credentials on disk

Use this only in controlled environments with proper authorization and legal compliance.

---

## Files Generated

- **Log File:** `C:\ProgramData\LoginMonitor\login_logs.txt`

---

## Troubleshooting

### Service won't start
- Check administrator privileges
- Verify `pywin32` is installed
- Check log file for error messages
- Ensure Security Event Log is accessible

### No events being logged
- Service might not have permission to read Security Event Log
- Events might be filtered out by the hardcoded Event IDs
- Log directory might have permission issues

### Log file grows too large
- Currently no automatic rotation - manual cleanup needed
- Monitor disk space regularly

---

## License & Disclaimer

This tool is provided for educational and authorized security monitoring purposes only. Ensure compliance with local laws and organizational policies before deployment.

---

**Last Updated:** November 13, 2025
