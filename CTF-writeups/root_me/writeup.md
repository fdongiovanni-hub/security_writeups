1. scanning machine with ```nmap -sC -sV -oN scan.txt 10.114.136.102```.
Open ports are 22 (ssh) and 80 (standard HTTP protocol port, Apache 2.4.41 on Ubuntu os, uses PHP)
2. used GoBuster ```gobuster dir -u http://10.114.136.102 -w /usr/share/dirb/wordlists/common.txt``` after common.txt installation to find relevant.

*Note: Added the -f flag to append a slash (/) and force directory discovery. Directories that previously returned a 301 redirect (pointing to their / version) now return a 200 OK status. Meanwhile, .php files like /index.php/ still return 200 OK with the exact same response size due to Apache's default AcceptPathInfo behavior.*

3. ```curl -s http://10.114.136.102/panel/``` to go to the hidden /panel/ folder. served a default index file.
- action="" submits the form data back to the exact same URL (/panel/).
- method="POST" sends data inside the hidden HTTP request body
- enctype="multipart/form-data" is specifically required to transmit binary/text files to the server.
