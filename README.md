# security_writeups
## TryHackMe
### Lab Environment: WSL2 Networking Setup

When doing network exercises on TryHackMe, using the default WSL2 settings can break things. For example, **Reverse Shells** will fail, and security tools won't communicate properly. 

To fix this, I changed two things: enable **Mirrored Mode** and run **OpenVPN inside Linux**.

### 1. Changing to Mirrored Mode
By default, WSL2 hides your Linux system inside a virtual "bubble" with a fake IP address (like `172.31.x.x`). Internet traffic can go out, but TryHackMe targets cannot send traffic back in because they get blocked by this bubble.

To fix this, I created a configuration file on your Windows host at `C:\Users\<YourUsername>\.wslconfig` and added:

```ini
[wsl2]
networkingMode=mirrored
dnsTunneling=true
```

### 2. Running OpenVPN inside Linux
Open your Linux terminal and start the VPN with this command:
   ```bash
   sudo openvpn <your_file_name>.ovpn
   ```
Keep that terminal tab open to maintain the connection, and open a new tab to run your tools.

It creates a virtual network interface inside Linux called `tun0` (Tunnel 0). Because the VPN is running natively inside Linux, hacking tools like `nmap` or `netcat` can send packets directly to the TryHackMe laboratory without any Windows errors.
