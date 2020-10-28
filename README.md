# Windows Privilege Escalation Cheat Sheet
Hi There today I published a checklist of strategies on Linux Privilege Escalation by [URL:Tib3rius]

## Windows Privilege Escalation Tools :

1- PowerUp: https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1
  example of usage: 
  - first get Powershell sessions 
    * powershell -exec bypass
  - . .\PowerUp.ps1
  - Invoke-AllChecks
  
2- SharpUp: 
  - Code: https://github.com/GhostPack/SharpUp
  - Pre-Compiled: https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/SharpUp.exe
  example of usage:
  - .\SharpUp.exe
  
3- Seatbelt:
  - Code: https://github.com/GhostPack/Seatbelt
  - Pre-Compiled: https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Seatbelt.exe
  example of usage:
  - .\Seatbelt.exe all
 
4- WinPEAS:  https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS
  example of usage:
  - WinPEAS.exe
  
5- accesschk.exe:
  - AccessChkis an old but still trustworthy tool for checking user access control rights.
  
## Windows Privilege Escalation Techniques:
1- Kernel Exploits (last choice):
  - First Enumerate Windows version/patch level (systeminfo).
  - Find exploits on (searchsploit, Google, ExploitDB, GitHub)
  - Compile & run
 * Tools to ease the proccess of finding the correct exploit:
  - Windows Exploit Suggester: https://github.com/bitsadmin/wesngPrecompiled 
- Pro Tip: First Check Those Kernel Exploits: https://github.com/SecWiki/windows-kernel-exploits
  - Watson: https://github.com/rasta-mouse/Watson
  
2- Service Exploits:
   - Insecure Service Permissions
      - NOTE: if you can change a service configuration but cannot stop/start the service you may on RABBIT HOLE
   - Unquoted Service Path
   - Weak Registry Permissions
   - Insecure Service Executables
   - DLL Hijacking
  
3- Registery Exploits
    * AutoRun executables
      - check for writable AutoRun executables
        > .\winPEASany.exequiet applicationsinfo
      - then use accesschk.exe to verify the permissions on each one:
        > .\accesschk.exe /accepteula -wvu "[file PATH]"
    
    * AlwaysInstallElevated
      - NOTE: Two Registry settings must be enabled for this to work.
        The “AlwaysInstallElevated” value must be set to 1 
        for both the local machine:
        HKLM\SOFTWARE\Policies\Microsoft\Windows\Installerand 
        the current user:
        HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
        If either of these are missing or disabled, the exploit will not work.
  
        - check both registry values by winPEAS
          > .\winPEASany.exequiet windowscreds
        - Then Create a new reverse shell with msfvenom, using the msi format, and save it with the .msi extension
        -  msiexec /quiet /qn /i [the path ov created reverse shell e.g. C:\PrivEsc\reverse.msi]
        
4- Passwords
