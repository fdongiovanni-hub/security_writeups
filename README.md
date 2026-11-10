# security_writeups
## TryHackMe
### Lab Environment: WSL2 Networking Setup

When doing network exercises on TryHackMe, using the default WSL2 settings breaks things. For example, **Reverse Shells** fail because security tools cannot communicate properly across the two systems. To fix this, I changed two things: I enabled **Mirrored Mode** and I run **OpenVPN inside Linux**.

### 1. Enabling Mirrored Mode
By default, WSL2 hides Linux inside a virtual bubble with a fake IP address (like `172.31.x.x`). Internet traffic can go out, but TryHackMe targets cannot send traffic back in because they get blocked. 

To fix this, I created a configuration file on my Windows host at `C:\Users\fedon\.wslconfig` and added this block:

```ini
[wsl2]
networkingMode=mirrored
dnsTunneling=true
```

This pops the virtual bubble. Linux now mirrors and shares the exact same network card and IP address as my Windows host (e.g., `10.126.228.79`). When I run `ip a s`, I can see my real network interface, allowing TryHackMe target machines to connect straight back to my Linux terminal.

### 2. Running OpenVPN Inside Linux
If I run the TryHackMe OpenVPN file on Windows, the VPN tunnel stays on Windows, and my Linux tools cannot see the targets. To connect the laboratory network directly to Linux, I run this command in my terminal:

```bash
sudo openvpn <my_profile_name>.ovpn
```

This creates a virtual network interface inside Linux called `tun0`. Because the VPN runs natively inside Linux, hacking tools like `nmap` or `netcat` can send packets directly to the TryHackMe sandbox without any cross-OS errors.
