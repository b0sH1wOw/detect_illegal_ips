# Illegal IP Detection Script
## Overview
This script is designed to run on a remote server to detect and block illegal IP addresses based on their interaction with an Nginx server. It uses the server's logs to determine the behavior of clients and applies iptables rules to block any IP addresses that exceed certain thresholds of illegal activity.
## Requirements
- Ensure you have permission to run `sudo` without a password on the server.
- The script relies on the `config.py` file for configuration settings.
- Nginx must be installed and configured to log requests to the specified log path.
## Installation
No installation is required. Simply place the script on the server and ensure it has execute permissions.
## Usage
To run the script, use the following command:
```bash
nohup python detect_illegal_ips.py > illegal_ips.log 2>&1 &
```
This command will run the script in the background and redirect both standard output and standard error to `illegal_ips.log`.
## Features
- Parses Nginx logs to identify legal and illegal requests based on predefined rules.
- Calculates the rate of illegal requests per IP address.
- Blocks IP addresses that exceed a specified threshold of illegal requests or illegal request rate using iptables.
- Saves the updated iptables rules to a file for persistence across reboots.
## Configuration
The script uses the following parameters from the `config.py` file:
- `route_method_rules`: Dictionary of allowed HTTP methods for specific routes.
- `nginx_log_path`: Path to the Nginx access log file.
- `nginx_log_pattern`: Regular expression pattern to match and extract information from log entries.
- `white_list`: List of IP addresses that are whitelisted and will not be blocked.
- `illegal_number_threshold`: Threshold number of illegal requests that triggers IP blocking.
- `illegal_rate_threshold`: Threshold rate of illegal requests that triggers IP blocking.
- `iptables_rules_path`: Path to the file where iptables rules are saved.
## How it Works
1. The script reads the Nginx log file and parses each entry to determine if it's legal or illegal based on the `route_method_rules`.
2. It calculates the rate of illegal requests for each IP address.
3. If an IP address exceeds the `illegal_number_threshold` or `illegal_rate_threshold`, it is considered for blocking.
4. The script checks if the IP address is already in the iptables rules. If not, it adds the IP address to the iptables `INPUT` chain to block it and saves the iptables rules.
5. The script runs in an infinite loop, checking for illegal IPs every 60 seconds.
## Logging
All output from the script, including any errors or actions taken, is logged to `illegal_ips.log`.
## Support
For support or questions, please contact the system administrator or the developer responsible for maintaining this script.
## License
This script is provided without any warranty. You are free to use and modify it according to your needs.
