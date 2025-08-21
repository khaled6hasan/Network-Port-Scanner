##  🔍 Advanced Python Port Scanner

A fast and feature-rich port scanner written in Python with advanced options like service fingerprinting, multi-threading, colored output, and report generation.

---

## ✅ Features

✔ Multi-threaded scanning for speed
✔ Two scan types:

- Connect Scan (default)

- SYN Scan (requires root/admin privileges)
✔ Service Fingerprinting: Detects services like HTTP, FTP, SSH
✔ Colored output for better visibility
✔ Progress bar using tqdm
✔ Saves results to a report file
✔ Ethical Scan Warning for safety

---

## 🛠 Requirements

- Python 3.7+
- Install dependencies:

```bash
pip install colorama tqdm

```

---

## 🚀 Usage

- Basic Scan

```bash
python port_scanner.py --target example.com --ports 1-1000

```

- SYN Scan (requires root/admin)

```bash
sudo python port_scanner.py --target 192.168.1.1 --scan syn

```

- Save Results to File

```bash
python port_scanner.py --target 192.168.1.1 --output report.txt

```

---

## 🔍 Example Output

![portscann1](https://github.com/khaled6hasan/Network-Port-Scanner/blob/main/portscann1.PNG)
![portscann2](https://github.com/khaled6hasan/Network-Port-Scanner/blob/main/portscann2.PNG)
![portscann3](https://github.com/khaled6hasan/Network-Port-Scanner/blob/main/portscann3.PNG)
![portscann4](https://github.com/khaled6hasan/Network-Port-Scanner/blob/main/portscann4.PNG)

---

## ⚠ Ethical Disclaimer

This tool is for educational and authorized security testing purposes only.
Do NOT use it to scan targets without explicit permission. Unauthorized scanning is illegal.

---

## 📂 Project Structure

```bash
port_scanner.py
README.md
requirements.txt

```
---

## 📝 Author

Made with ❤️ by [ Khaled Hasan Nahid ]

---

## 📜 License

- This project is licensed under the MIT License. Feel free to use and modify!
