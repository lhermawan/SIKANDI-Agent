# SIKANDI-Agent: Pedoman Instalasi & Konfigurasi

SIKANDI-Agent adalah *service* berbasis Python ringan yang dipasang pada server/VM target. Agen ini berfungsi melakukan monitoring (CPU/RAM/Disk), mendeteksi anomali keamanan (File Integrity, Brute Force), hingga mengeksekusi tindakan isolasi jaringan (blokir IP via `iptables`) berdasarkan perintah dari Dashboard SIKANDI.

---

## 🛠️ Prasyarat Sistem (Prerequisites)

Sebelum melakukan instalasi pada server target, pastikan server memenuhi spesifikasi berikut:
1. **OS Linux** (Ubuntu / Debian / CentOS / RHEL)
2. **Python 3.8** atau lebih baru, beserta `pip` (`python3-pip`) dan modul Virtual Environment (`python3-venv`).
3. **Akses Root / Sudo:** Mutlak dibutuhkan karena agen akan membaca log sistem (`/var/log/auth.log` dan `/var/log/fail2ban.log`) serta mengeksekusi blokir via `fail2ban`/`iptables`.
4. **Fail2ban (Sangat Direkomendasikan):** Digunakan untuk membaca log blokir otomatis dan mengeksekusi perintah blokir dari SOC SIKANDI agar lebih rapi (*tidak menumpuk di iptables mentah*).
5. (Opsional) **Node.js & PM2** untuk menjalankan agen di latar belakang *(background service)*.

---

## 🚀 Langkah Instalasi

### 1. Salin File Agent
Pindahkan folder `sikandi-agent` dari repositori utama ke server target (misal diletakkan di `/opt/sikandi-agent/`).
```bash
sudo cp -r sikandi-agent /opt/
cd /opt/sikandi-agent
```

### 2. Install Dependencies (Menggunakan Virtual Environment)
Pada OS Linux versi modern (seperti Ubuntu 23+ atau Debian 12+), instalasi *library* secara global diblokir untuk keamanan. Kita akan menggunakan praktik terbaik yaitu *Virtual Environment* (VENV):

```bash
# Install paket venv jika belum tersedia di OS
sudo apt update && sudo apt install python3-pip python3-venv -y

# Buat environment terisolasi bernama 'venv' di dalam folder sikandi-agent
python3 -m venv venv

# Instal library dari requirements.txt langsung ke dalam venv
sudo ./venv/bin/pip3 install -r requirements.txt
```

### 3. Konfigurasi Awal (config.yaml)
Buka file `config.yaml` menggunakan editor teks (nano/vim):
```bash
sudo nano config.yaml
```
Sesuaikan `url` dengan alamat server utama SIKANDI Anda:
```yaml
api:
  url: "https://sikandi.ciamiskab.go.id/api/v1/agent"
  token: "" 
```
*Catatan: Biarkan token kosong (`""`). Agen akan menanyakannya saat pertama kali dijalankan.*

---

## 🔐 Proses Registrasi Agent

SIKANDI mengamankan setiap agen menggunakan sistem *Zero Trust Registration*.
Jalankan perintah berikut untuk memulai registrasi menggunakan Python bawaan venv:
```bash
sudo ./venv/bin/python3 agent.py
```

**Alur Registrasi:**
1. Di layar, agen akan mendeteksi token kosong dan meminta **Registration Token**. 
   *(Dapatkan Token Registrasi Global ini dari Menu Settings > General di Dashboard SIKANDI).*
2. Setelah di-Enter, agen akan mengirim data *Hostname* ke SIKANDI.
3. **PENTING:** Buka Dashboard Web SIKANDI -> Menu **Server Agents**. Anda akan melihat agen baru berstatus "Pending". Klik tombol **Approve**.
4. SIKANDI akan memunculkan popup berisi **Token Sanctum Rahasia**.
5. *Copy* token tersebut, dan *Paste* kembali ke terminal server target.
6. Selesai! `config.yaml` akan otomatis diperbarui dan agen mulai memonitor server. Tekan `Ctrl+C` untuk mematikan sementara.

---

## 🏃‍♂️ Menjalankan di Latar Belakang (Production Mode)

Agar agen tetap hidup secara otomatis di latar belakang (*background*), Anda dapat memilih salah satu dari dua metode berikut. Pastikan dijalankan sebagai **root** karena agen butuh memodifikasi iptables/fail2ban.

### Opsi A: Menggunakan Systemd (Direkomendasikan - Native Linux)

Metode ini tidak memerlukan instalasi tambahan (seperti Node.js/PM2) karena `systemd` adalah bawaan mayoritas OS Linux.

1. Buat file service baru:
   ```bash
   sudo nano /etc/systemd/system/sikandi-agent.service
   ```
2. Isi file tersebut dengan konfigurasi berikut (pastikan path direktori `/opt/sikandi-agent` sudah sesuai):
   ```ini
   [Unit]
   Description=SIKANDI Intelligent Security Monitoring Agent
   After=network.target

   [Service]
   Type=simple
   User=root
   WorkingDirectory=/opt/sikandi-agent
   ExecStart=/opt/sikandi-agent/venv/bin/python3 /opt/sikandi-agent/agent.py
   Restart=always
   RestartSec=10

   [Install]
   WantedBy=multi-user.target
   ```
3. Reload daemon, mulai service, dan buat agar otomatis berjalan saat *boot*:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl start sikandi-agent
   sudo systemctl enable sikandi-agent
   ```
4. Untuk melihat log secara real-time:
   ```bash
   sudo journalctl -u sikandi-agent -f
   ```

### Opsi B: Menggunakan PM2 (Berbasis Node.js)

Metode ini cocok jika di server Anda sudah terinstal Node.js dan Anda terbiasa mengelola service dengan PM2.

```bash
# Install PM2 jika belum ada (membutuhkan Node.js)
sudo npm install -g pm2

# Jalankan Agent menggunakan interpreter Python3 yang ada di venv
sudo pm2 start agent.py --name "sikandi-agent" --interpreter ./venv/bin/python3

# Simpan state PM2 agar auto-start saat server restart
sudo pm2 save
sudo pm2 startup
```

---

## 🛡️ Fitur Otomatisasi (Blacklist Sync & Fail2ban)

Agen SIKANDI memiliki *thread* **Blacklist Sync** yang berjalan setiap 30 detik.
1. Agen akan mengunduh daftar IP yang di-blokir *(HitL Execution)* dari SIKANDI Utama.
2. Jika ada IP penyerang baru, agen akan otomatis mengeksekusi perintah blokir via **Fail2ban**:
   `fail2ban-client set sshd banip {IP}`
3. *(Fallback)* Jika Fail2ban tidak tersedia, agen otomatis menggunakan:
   `iptables -I INPUT 1 -s {IP} -j DROP`
4. Seluruh log eksekusi blokir dapat dilihat menggunakan perintah:
   ```bash
   sudo pm2 logs sikandi-agent
   ```

---

## 🧪 Testing Mode
Jika Anda ingin mengetes alur insiden keamanan dari agen ke Dashboard *tanpa* melakukan serangan sungguhan, jalankan menggunakan argumen test:
```bash
sudo ./venv/bin/python3 agent.py --test-security
```
Agen akan mengirimkan serangan *Brute Force Mockup* ke dashboard setiap 10 detik.
