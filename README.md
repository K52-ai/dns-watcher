🚀 DNS-WATCHER

⚡ A fast and lightweight DNS Traffic Analyzer written in Go.

DNS-Watcher is a command-line forensic tool that analyzes `.pcap` files to extract and inspect DNS traffic. It identifies top queried domains, maps them to their source IP addresses, and detects potential DNS Tunneling (data exfiltration) based on domain length and query patterns.

✨ Features

🛡️ **Fast PCAP Parsing:** Uses `gopacket` for high-performance packet processing.
🔍 **DNS Filtering:** Extracts only DNS traffic (Port 53) from noisy network captures.
📊 **Top Domains:** Displays the most frequently queried domains.
⚠️ **Tunneling Detection:** Flags suspiciously long subdomains (a common indicator of DNS Tunneling).
🌐 **Source Mapping:** Identifies which IP addresses made the suspicious queries.
🎨 **Colorful CLI:** Clean, hacker-style terminal output with ASCII banner.

📋 Requirements

🐧 Linux, macOS, or Windows
🐹 Go 1.21 or later
📦 Git (optional)
📂 A `.pcap` or `.cap` file (You can download sample PCAPs from Wireshark or openpcap).

🛠️ Installation

Step 1 — Clone the repository

    git clone https://github.com/K52-ai/dns-watcher.git
    cd dns-watcher

Step 2 — Download dependencies

    go mod tidy

Step 3 — Build the tool

    go build -o dns-watcher dns-watcher.go

Step 4 — Make it executable (optional)

    chmod +x dns-watcher

▶️ Usage

Step 1 — Run the tool (Interactive mode)

    ./dns-watcher

Step 2 — The tool will prompt you for the file path

    Enter PCAP file path: /path/to/your/file.pcap

Step 3 — Run the tool directly with the file path

    ./dns-watcher /path/to/your/file.pcap

📝 How It Works

*   **`go mod init` / `go get`**: Initializes the Go module and downloads the `gopacket` library.
*   **`go build`**: Compiles the Go source code into a single executable binary.
*   **`./dns-watcher`**: Starts the analyzer and prompts for the PCAP file.
*   **Parsing**: The tool reads the PCAP file, filters only DNS packets (Port 53), and counts how many times each domain was queried.
*   **Detection**: It ignores local network queries (like `.local`, `.arpa`) and flags any domain with a subdomain longer than 30 characters.
*   **Output**: Prints a summary of Top Domains and suspicious activity directly to the terminal.

📊 Results

🟢 **Total DNS Requests:** Total number of DNS queries found in the file.
🟢 **Unique Domains:** Number of distinct domains queried.
🔴 **Suspicious Domains:** Domains flagged as potential DNS Tunneling (highlighted in Red).

⚠️ Important Notes

🛡️ This tool is designed for analyzing **DNS traffic only**. Other protocols (HTTP, TCP) will be ignored.
🔍 A suspicious domain doesn't always mean a compromise; verify the context.
⚡ Local domains (like Active Directory queries) are automatically filtered out to reduce false positives.

⚖️ Responsible Use

Use DNS-Watcher only on network captures you own or have explicit permission to analyze. Respect privacy and applicable laws.

📜 License

MIT License. See LICENSE for details.

👨‍💻 Author

K52-ai
🔗 GitHub Repository
