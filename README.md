# ⚡ Havoc 

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/FrontierTM/Havoc?style=for-the-badge)](https://goreportcard.com/report/github.com/FrontierTM/Havoc)
[![Go Version](https://img.shields.io/github/go-mod/go-version/FrontierTM/Havoc?style=for-the-badge&logo=go)](https://golang.org)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=for-the-badge)](http://makeapullrequest.com)
[![Issues](https://img.shields.io/github/issues/FrontierTM/Havoc?style=for-the-badge)](https://github.com/FrontierTM/Havoc/issues)

**Havoc** is a high-performance, asynchronous multi-protocol account checker written in Go. Engineered for extreme concurrency and memory efficiency, it allows for high-speed validation across various network protocols simultaneously.

## 🚀 Key Features

* **⚡ Concurrency-First:** Leverages Go's goroutines and channels for massive parallel processing and high CPM (Checks Per Minute).
* **🔌 Multi-Protocol Support:**
    * **SSH:** Native implementation for high-speed secure shell validation.
    * **Telnet:** Asynchronous telnet handshake and login verification.
    * **RDP:** (Coming Soon) Remote Desktop Protocol support via native Go wrappers.
    * **More Soon:** Support for more protocols and also more scanners.
* **🛠️ Modular Design:** Easy-to-extend interface system for adding new protocol modules.

---

## 🛠️ Installation

### Prerequisites
- [Go](https://golang.org/dl/) (1.21 or higher recommended)

### Setup
1. **Clone the repository**
   ```bash
   git clone [https://github.com/YourUsername/Havoc.git](https://github.com/YourUsername/Havoc.git)
   cd Havoc
   go mod download
   go build -o havoc main.go
   ```
## **📖 Usage**

Since the project is heavly under development there will be a **WIKI** to explain how to workaround.



## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. The developer is not responsible for any misuse or damage caused by this program. Use it only on systems you own or have explicit permission to test.



## 📄 License

Distributed under the MIT License. See LICENSE for more information.
