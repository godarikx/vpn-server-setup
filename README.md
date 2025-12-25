# VPN Server Setup

Automated security hardening script for Ubuntu VPN servers. One-command setup for SSH hardening, firewall, fail2ban, Docker installation, and system security configuration.

## Features

- 🔐 **SSH Hardening**: Changes SSH port, disables password authentication, enables key-based auth, and blocks root login
- 🛡️ **fail2ban**: Automatic installation and configuration with custom ban time and retry limits
- 🔥 **UFW Firewall**: Complete firewall setup with ICMP protection and server hiding
- 👤 **User Management**: Creates new sudo user and switches execution context
- 🐳 **Docker Installation**: Installs Docker and adds user to docker group for container management
- 🚀 **Performance**: Enables TCP BBR for traffic acceleration
- 🔒 **System Hardening**: SYN-flood protection and server hiding via sysctl
- 💾 **Swap Management**: Creates or resizes swap file with optimal swappiness (10)
- 🌐 **IPv6 Disabling**: Disables IPv6 to ensure consistent geolocation

## Requirements

- Ubuntu (tested on 20.04+, but should work on other versions)
- Root access
- Internet connection for package installation

## Installation

### Quick Install (as root)

If you are already logged in as root:

```bash
bash <(wget -qO- https://raw.githubusercontent.com/godarikx/vpn-server-setup/master/install.sh)
```

**Note:** Do NOT use `sudo` with process substitution `<(...)`. If you need to run as root, either:

- Log in as root directly, or
- Use the manual install method below

### Manual Install

```bash
wget https://raw.githubusercontent.com/godarikx/vpn-server-setup/master/install.sh
chmod +x install.sh
sudo ./install.sh
```

Or using curl:

```bash
curl -o install.sh https://raw.githubusercontent.com/godarikx/vpn-server-setup/master/install.sh
chmod +x install.sh
sudo ./install.sh
```

## Usage

Simply run the script and follow the prompts:

```bash
sudo ./install.sh
```

The script will guide you through the setup process:

1. Enter username to create
2. Enter SSH port (1-65535)
3. Enter SSH public key
4. Enter swap size in GB (0 to skip)
5. Review configuration and confirm
6. Enter password for the new user

**Important:** SSH public key is mandatory because password authentication is disabled for all users (including root). The SSH configuration applies equally to all users.

## What the Script Does

1. **User Creation**: Creates a new user with sudo privileges and switches execution context
2. **SSH Keys Setup**: Removes root's authorized_keys and sets up SSH keys for the new user (required via `-k` flag)
3. **Docker Installation**: Installs Docker using the official installation script and adds the user to the docker group
4. **SSH Configuration**:
   - Changes SSH port to specified value
   - Disables password authentication for all users (including root)
   - Enables public key authentication
   - Disables root login
   - Restricts SSH access to the created user only (AllowUsers)
   - SSH configuration applies equally to all users
5. **fail2ban Setup**:
   - Installs fail2ban if not present
   - Configures ban time (3600 seconds)
   - Sets max retry attempts (3)
   - Monitors SSH on the new port
6. **Firewall Configuration**:
   - Installs and configures UFW
   - Allows SSH on the new port
   - Configures ICMP rules for server hiding
7. **System Hardening**:
   - Enables SYN-flood protection (tcp_syncookies)
   - Hides server from ICMP echo requests
   - Enables TCP BBR for traffic acceleration
8. **Swap Configuration**:
   - Creates new swap file if it doesn't exist
   - Resizes existing swap to specified size
   - Sets swappiness to 10 (optimal for servers - use swap only when RAM is low)
   - Adds swap to /etc/fstab for persistence
9. **IPv6 Disabling**: Creates systemd service to disable IPv6 permanently

## Important Notes

⚠️ **Before running the script:**

1. **SSH Keys**: You must provide your public SSH key when prompted. Password authentication is disabled for all users (including root), so SSH key is mandatory. The SSH configuration applies equally to all users.
2. **Current Session**: Keep your current SSH session open until you verify the new configuration works.
3. **Port Access**: Make sure the new SSH port is not blocked by your VPS provider's firewall.
4. **Backup**: The script creates backups of modified configuration files automatically.
5. **Docker Group**: After installation, you may need to log out and log back in for docker group permissions to take effect, or run `newgrp docker`

## Troubleshooting

### Error: "bash: /dev/fd/63: No such file or directory"

This error occurs when using `sudo` with process substitution `<(...)`. The process substitution doesn't work with `sudo` because it creates a new process.

**Solution:**

- If you're already root, remove `sudo` from the command
- Or use the manual install method to download the script first, then run it with `sudo`

### Cannot connect after running the script

1. Check if the new SSH port is open in your VPS provider's firewall
2. Verify your SSH key is properly configured
3. Check SSH service status: `sudo systemctl status ssh`

### Docker permission denied

If you get "permission denied while trying to connect to the docker API" error:

1. Make sure you've logged out and logged back in after running the script (docker group changes require a new session)
2. Or run: `newgrp docker` to activate the docker group in current session
3. Verify you're in the docker group: `groups`

### fail2ban warnings

The Python SyntaxWarnings from fail2ban are harmless and can be ignored. They don't affect functionality.

### User already exists

If the specified username already exists, the script will skip user creation but still add the user to the sudo and docker groups.

## Security Considerations

- Root login is disabled via SSH
- Password authentication is disabled (key-based only)
- fail2ban protects against brute-force attacks
- Firewall is configured with strict rules
- Server is hidden from ICMP requests
- IPv6 is disabled for consistent geolocation

## Files Modified

The script modifies the following system files (backups are created):

- `/etc/ssh/sshd_config`
- `/etc/fail2ban/jail.local`
- `/etc/ufw/before.rules`
- `/etc/sysctl.conf`
- `/etc/fstab`
- `/swapfile`
- `/etc/systemd/system/disable-ipv6.service`

## License

This project is open source and available under the MIT License.

## Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/godarikx/vpn-server-setup/issues).

## Disclaimer

This script modifies critical system configurations. Use at your own risk. Always test in a non-production environment first and ensure you have proper backups.
