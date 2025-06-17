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
