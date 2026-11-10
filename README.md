# security_writeups
## TryHackMe
### Lab Environment: Advanced WSL2 Networking Setup

To prevent common virtualization barriers during practical exercises (such as broken reverse shells, Metasploit handler drops, or routing conflicts with OpenVPN), the local environment has been configured using a two-step workaround: **WSL Mirrored Mode** combined with **In-Distro VPN routing**.

### 1. Host Interface Mirroring (Mirrored Mode)
By default, WSL2 acts as a virtual machine hidden behind a Hyper-V NAT switch (`172.31.x.x`), which drops inbound connections initiated by remote targets. 

To bridge this isolation layer, a global configuration file has been deployed on the Windows host at `C:\Users\<Username>\.wslconfig`:

```ini
[wsl2]
networkingMode=mirrored
dnsTunneling=true
```

**Outcome:** Linux discards the virtual NAT architecture and directly mirrors the physical network adapters of the Windows host. Running `ip a s` inside the terminal shows the exact same IP address as the physical Wi-Fi/Ethernet interface (e.g., `10.126.228.79`), ensuring the local system is fully reachable by inbound traffic.

### 2. Native Inside-WSL Tunneling (OpenVPN)
Running the TryHackMe OpenVPN configuration on the Windows host isolates the encrypted tunnel from the Linux subsystem, breaking the toolsets.

**Implementation Workflow:**
1. Download the personal `.ovpn` lab access profile directly into the Linux file system.
2. Initialize the cryptographic tunnel natively inside the Linux environment:
   ```bash
   sudo openvpn <profile_name>.ovpn
   ```
   
**Outcome:** The virtual network interface (`tun0`) is bound directly within the Linux kernel, preventing cross-OS encapsulation issues and ensuring that all raw network scripts correctly route their payloads into the private TryHackMe sandbox.
