<h1 align="center">SHAR — SHA256 Dictionary Password Cracker</h1>

<p align="center">
  A fast, multi threaded, CPU based SHA256 dictionary cracker written in C
</p>

<p align="center">
  <img src="https://img.shields.io/badge/language-C-blue">
  <img src="https://img.shields.io/badge/library-OpenSSL-green">
  <img src="https://img.shields.io/badge/type-Dictionary%20Attack-red">
  <img src="https://img.shields.io/badge/%E2%9A%99%EF%B8%8F-Multi%20Threading-yellow">
  <img src="https://img.shields.io/badge/version-2.0.0-purple">
</p>

---

## 📌 Overview

This is version 2 of my personal SHA256 dictionary cracker, a significant rewrite of the original single threaded tool, rebuilt with performance in mind.

**What changed from v1:**
- **Multi threaded** - With multi threading and some I/O optimization, now this tool is incredibly fast
- **Lock free work distribution** - Atomic batch-based indexing; no mutex contention
- **Zero copy file loading** - Uses `mmap` on Linux/macOS to load the dictionary directly into memory without an extra copy
- **Cache friendly design** - `PasswordEntry` structs are padded to 64 bytes to avoid false sharing across CPU cores
- **Reusable hash context** - Each thread maintains its own `EVP_MD_CTX`, avoiding per-hash allocation overhead
- **Pre converted hash** - The target hex hash is converted to raw bytes once at startup, making comparisons a simple `memcmp`

Still educational in nature - built to learn about password cracking, concurrency, and low-level optimization in C.

---

## ⚙️ How It Works

1. The dictionary file is loaded entirely into memory (using `mmap` where supported)
2. Each line is indexed into a `PasswordEntry` array via pointer arithmetic, no `strdup`, no extra allocations
3. 16 worker threads atomically claim batches of 50,000 passwords at a time
4. Each thread hashes its batch using OpenSSL's EVP interface and compares against the target
5. On a match, the password is printed and all threads stop

---

## 🛠️ Compilation

Make sure OpenSSL development libraries are installed, then compile with GCC:

```bash
gcc -O2 -o cracker shar.c -lssl -lcrypto -lpthread
```

> `-O2` is recommended for best performance.

### Dependencies

#### Debian / Ubuntu / Kali Linux

```bash
sudo apt install libssl-dev
```

#### Arch Linux / Manjaro

```bash
sudo pacman -S openssl
```

#### Windows (via MSYS2)

1. Download and install MSYS2 from https://www.msys2.org/
2. Open the **MSYS2 UCRT64** terminal and run:

```bash
pacman -Syu
pacman -S mingw-w64-ucrt-x86_64-gcc
pacman -S mingw-w64-ucrt-x86_64-openssl
```

3. Compile normally with the same GCC command above.

---

## 📖 Usage

Run the compiled binary from a terminal:

```bash
./cracker
```

You will be prompted for:

1. **Dictionary file path** - A wordlist file (e.g. `rockyou.txt`), one password per line
2. **SHA256 hash** - The 64 character hex hash you want to crack

**Example session:**

```
[+] Enter the path of the dictionary : /home/user/rockyou.txt
[*] Loading dictionary into memory...
[*] Loaded 14344391 passwords. Starting 16 threads...

[++++++] Password found : password123

[*] Total time taken = 0.0325 seconds
```

**Special commands** (at the file path prompt):

| Command | Action          |
|---------|-----------------|
| `exit`  | Quit the program|


demonstrating :- 



---

## ⚠️ Disclaimer

This tool is built **strictly for educational and cybersecurity research purposes**.  
Only use it against hashes you own or have explicit permission to test.  
The author takes no responsibility for misuse.

---

## 👤 Author

**Piyumila Perera**  
Version 2.0.0