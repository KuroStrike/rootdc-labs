# RootDC — self-hosted AD labs

Run the RootDC beginner Active Directory labs entirely on your own computer, with
no account and no internet access to the lab. One script builds the same training
domain as the hosted version, so the bundled manuals apply as-is.

This kit includes three labs:
- **Kerberoasting 101**
- **AS-REP Roasting**
- **Password Spray**

> **Authorized training use only.** Everything here is for studying and detecting
> these attacks in a lab you own. Build it on an **isolated VM** on a host-only or
> internal-only network, with no route to any production network or to the
> internet-facing side of your home/office LAN. The accounts created are
> intentionally weak and must never exist on a real network.

## What you get
A `fallen.local` domain controller, one shared low-privilege starting account
(`attacker` / `Welcome1!`), and the target accounts for each lab:

| Lab | Targets | High-value account |
|-----|---------|--------------------|
| Kerberoasting | 4 service accounts with SPNs and weak passwords | `svc_admin` (Domain Admins) |
| AS-REP Roasting | 3 accounts with Kerberos pre-auth disabled | `svc.backup` (Backup Operators) |
| Password Spray | 5 weak accounts + 8 decoys, with a lockout policy | `admin.svc` (Domain Admins) |

The exact account names and passwords are written to `C:\RootDC\scenarios\*.txt`
on the VM after setup.

## What you need
- A 64-bit PC (Windows, Linux, or an Intel Mac) with a hypervisor:
  VirtualBox (free), VMware Workstation/Fusion, or Hyper-V.
  **Note:** Apple Silicon Macs (M1–M5) cannot run Windows Server, which is x86.
- About **8–12 GB RAM** free and ~40 GB disk.
- Roughly 30–45 minutes to set it up.

---

## Step 1 — Get Windows Server 2022 (free, 180 days)
Download the **Windows Server 2022 Evaluation** ISO from Microsoft:
<https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022>
(Choose the ISO. The evaluation is free for 180 days — plenty for a thesis.)

## Step 2 — Create the lab VM
1. New VM: 2 vCPU, 4–6 GB RAM, 40 GB disk, boot the ISO.
2. Install Windows Server 2022 **(Desktop Experience)**. Set an Administrator
   password you will remember.
3. **Networking — important:** set the VM network adapter to **host-only**
   (VirtualBox/VMware) or an **Internal** switch (Hyper-V). This keeps the
   vulnerable domain off your real network. You do not need internet in the VM.

## Step 3 — Build the domain and the labs
1. Copy this whole folder into the VM (shared folder, or just paste the files).
2. Open **PowerShell as Administrator** and run:
   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass -Force
   cd <folder with Setup-Lab.ps1>
   .\Setup-Lab.ps1
   ```
   This sets up **all three** labs. For a single one:
   `.\Setup-Lab.ps1 -Scenario Kerberoast` (or `ASREP`, or `PasswordSpray`).
3. The VM installs AD and **reboots once**. Log back in as Administrator — the
   script resumes on its own and creates the accounts. If it does not resume,
   just run `.\Setup-Lab.ps1` again.

That is the whole target set up. Everything below is the exercise.

---

## Step 4 — Do the labs
Each attack is standard and uses the shared account `attacker` / `Welcome1!`.
Pick whichever setup you prefer; both use the same account.

### Option A — attack from a Linux VM (closest to the hosted lab)
Add a second small VM (Kali, or any Linux with Python) on the **same host-only
network**, point it at the DC's IP, and follow the bundled manual for each lab.
These use the public Impacket + hashcat workflow (e.g. `GetUserSPNs.py`,
`GetNPUsers.py`, `netexec`/`crackmapexec`, `hashcat`) exactly as written.

### Option B — no second VM (Windows only)
From a domain-joined Windows box (a second VM, or for study the DC itself), the
enumeration/request steps are possible with **Rubeus** or built-in PowerShell,
then crack offline with hashcat/john on any machine. Less realistic than Option
A, but needs only the one VM.

### Manuals (bundled)
- `manuals-kerberoasting-beginner.md`
- `manuals-asrep-roasting-beginner.md`
- `manuals-password-spray-beginner.md`

### Difference from the hosted lab
There is no automatic flag check or scoreboard here — that lives on the hosted
platform. Success = you crack the high-value account and authenticate as it. For
a thesis this is actually better: you can inspect every step and study the
detection side too (e.g. Event ID 4769 for Kerberoasting/AS-REP TGS requests,
4625/4771 for the spray, visible in the DC Security log).

## Teardown
Snapshot the VM before attacking so you can reset, and delete the VM(s) when
done. Nothing here should outlive the exercise.
