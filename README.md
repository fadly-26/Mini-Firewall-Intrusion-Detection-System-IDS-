# Mini Firewall & Intrusion Detection System (IDS)

Mini Firewall & Intrusion Detection System (IDS) adalah aplikasi simulasi keamanan jaringan berbasis terminal yang dibuat menggunakan C++ sebagai studi kasus penerapan Struktur Data dan Algoritma.

Program ini mensimulasikan sebuah jaringan kantor kecil. Dalam konteks simulasi, **program Mini IDS dianggap berjalan di perangkat Firewall**. Jadi, ketika PC di jaringan kantor mencoba mengakses suatu IP atau domain, trafik tersebut melewati firewall terlebih dahulu, lalu diperiksa oleh program ini.

Dengan kata lain, pengguna program berperan sebagai **administrator atau penguji sistem** yang memasukkan data simulasi paket jaringan. Input tersebut dianggap sebagai trafik yang berasal dari perangkat kantor, lalu diproses oleh Firewall + Mini IDS.

## Tujuan Program

Program ini dibuat untuk memperlihatkan bagaimana konsep Struktur Data dan Algoritma dapat diterapkan dalam studi kasus cyber security, khususnya:

- simulasi firewall
- simulasi intrusion detection system (IDS)
- filtering trafik berdasarkan IP, domain, dan port
- monitoring sesi aktif
- pencatatan log alarm keamanan
- analisis jalur serangan pada topologi jaringan
- perbandingan algoritma searching dan sorting
- analisis kompleksitas Big O

## Posisi Program dalam Jaringan

Program ini diposisikan sebagai sistem keamanan yang berjalan pada firewall.

```text
PC Kantor
   |
   v
Core Switch
   |
   v
Firewall + Mini IDS
   |
   v
Router
   |
   v
Internet / Target Luar
```

Saat pengguna mengisi input seperti:

```text
Perangkat asal : PC HRD
Target tujuan  : phishing.net
Port tujuan    : 443
Payload        : 120 KB
```

Maka maknanya adalah:

> PC HRD sedang mencoba mengakses phishing.net. Trafik tersebut melewati Firewall + Mini IDS, lalu program menentukan apakah paket tersebut ALLOWED atau BLOCKED.

## Arsitektur Topologi

Topologi jaringan yang digunakan adalah jaringan kantor kecil:

```text
                         Router
                           |
                   +-------------------+
                   | Firewall + Mini   |
                   | IDS               |
                   +-------------------+
                           |
                     Core Switch
   ________________________|________________________
  |          |          |        |          |       |
Web       Database   PC Admin  PC HRD   PC       PC
Server    Server                        Karyawan Karyawan
                                         1        2
```

Versi hubungan graph yang dipakai program:

```text
Router <-> Firewall + Mini IDS
Firewall + Mini IDS <-> Core Switch
Core Switch <-> Web Server
Core Switch <-> Database Server
Core Switch <-> PC Admin
Core Switch <-> PC HRD
Core Switch <-> PC Karyawan 1
Core Switch <-> PC Karyawan 2
```

Catatan penting:

- **Firewall + Mini IDS** adalah tempat program ini diposisikan.
- **PC Admin, PC HRD, PC Karyawan 1, dan PC Karyawan 2** adalah perangkat asal trafik.
- **Web Server dan Database Server** adalah aset internal yang dilindungi.
- **Database Server** dianggap sebagai aset paling kritis untuk analisis BFS.
- **Router** adalah penghubung jaringan kantor menuju internet, tetapi bukan perangkat asal trafik pada simulasi input.

## Alur Kerja Sistem

Alur program berjalan berbasis menu. Artinya, setiap fitur dijalankan berdasarkan pilihan admin/penguji, bukan otomatis berjalan semuanya sekaligus. Alur utamanya adalah input paket, simpan ke Queue, jalankan inspeksi firewall, lalu hasilnya disimpan sebagai sesi aktif atau alarm keamanan.

```text
[ Admin / Penguji menjalankan program ]
                         |
                         v
             [ MENU UTAMA APLIKASI ]
                         |
                         v
        [1] Tambah Paket Simulasi Trafik
                         |
                         v
        [ Pilih Perangkat Asal Trafik ]
        +-- PC Admin
        +-- PC HRD
        +-- PC Karyawan 1
        +-- PC Karyawan 2
                         |
                         v
[ Input Target IP/Domain + Port + Payload Size ]
                         |
                         v
            [ Smart Parser: isalpha Check ]
            +-- Ada huruf         -> tipeTarget = DOMAIN
            +-- Hanya angka/titik -> tipeTarget = IP
                         |
                         v
       [ Paket masuk ke Antrean Jaringan (Queue) ]
                         |
                         v
       [2] Admin dapat melihat isi Queue
                         |
                         v
       [3] Jalankan Firewall Inspection Engine
                         |
                         v
              [ FIFO Pop dari Queue ]
                         |
                         v
          [ Pengecekan 1: Array Blacklist ]
          +-- Target terdaftar -> status paket BLOCKED
          +-- Tidak terdaftar  -> lanjut cek port
                         |
                         v
          [ Pengecekan 2: BST Port Bahaya ]
          +-- Port terdeteksi -> status paket BLOCKED
          +-- Port aman       -> status paket ALLOWED
                         |
                         v
              [ Keputusan Firewall ]
              +-- ALLOWED
              |      |
              |      v
              | [ Simpan ke Linked List Sesi Aktif ]
              |
              +-- BLOCKED
                     |
                     v
        [ Simpan ke Stack Alert / Log Alarm SOC ]
                     |
                     v
        [ Simpan ke Vector Log untuk Sorting ]
                     |
                     v
        [ Tandai Perangkat Asal sebagai BERISIKO ]
                         |
                         v
          [ Looping sampai Queue kosong ]
                         |
                         v
              [ Hasil dapat dianalisis ]
              +-- [4] Lihat Stack Alert
              +-- [5] Lihat Linked List Sesi Aktif
              +-- [6] Lihat Topologi Graph
              +-- [7] BFS ke Database Server
              +-- [8] DFS Blast Radius
              +-- [9] Sorting Prioritas Alarm
              +-- [10] Searching Blacklist
                         |
                         v
                  [0] Keluar Program
                         |
                         v
      [ Bebaskan memori Linked List dan BST ]
                         |
                         v
                   [ Program Selesai ]
```

Pada bagian keputusan firewall, `ALLOWED` dan `BLOCKED` adalah status paket. Jika paket `BLOCKED`, paket tidak diteruskan ke target, tetapi perangkat asal tetap ditandai `BERISIKO` sebagai tanda bahwa perangkat tersebut perlu dianalisis lebih lanjut.

## Workflow Incident Response

Program ini dapat dibaca sebagai simulasi sederhana proses incident response.

1. Admin memilih perangkat asal trafik, misalnya `PC HRD`.
2. Admin memasukkan target IP/domain, port, dan ukuran payload.
3. Program mendeteksi tipe target secara otomatis sebagai `DOMAIN` atau `IP`.
4. Paket disimpan ke Queue sebagai antrean trafik.
5. Admin menjalankan inspeksi firewall melalui Menu `[3]`.
6. Program memproses paket satu per satu menggunakan prinsip FIFO.
7. Program memeriksa target pada blacklist domain/IP.
8. Program memeriksa port tujuan pada Binary Search Tree port berbahaya.
9. Jika paket aman, koneksi dicatat ke Linked List sesi aktif.
10. Jika paket berbahaya, paket diblokir, alert masuk ke Stack, data blocked disimpan ke Vector, dan perangkat asal ditandai `BERISIKO`.
11. Admin dapat membuka Graph untuk melihat status perangkat pada topologi.
12. Admin dapat menjalankan BFS untuk mencari jalur tercepat menuju `Database Server`.
13. Admin dapat menjalankan DFS untuk melihat blast radius atau jangkauan dampak dari perangkat berisiko.
14. Admin dapat menjalankan Sorting untuk mengurutkan log alarm berdasarkan payload.
15. Admin dapat menjalankan Searching untuk membandingkan Linear Search dan Binary Search pada blacklist.

## Penerapan Struktur Data & Algoritma

| Konsep | Implementasi pada Kode | Fungsi dalam Program |
|---|---|---|
| Struct | `PaketData`, `NodeSesi`, `NodeTree` | Menyusun data agar lebih rapi. `PaketData` menyimpan informasi paket, `NodeSesi` menyimpan sesi aktif, dan `NodeTree` menyimpan data port berbahaya. |
| Array | `domainBlacklist[]`, `ipBlacklist[]` | Menyimpan daftar domain dan IP berbahaya yang digunakan saat inspeksi firewall. |
| Queue | `queue<PaketData> antreanPaket` | Menjadi buffer paket jaringan. Paket yang masuk disimpan dulu, lalu diproses berurutan menggunakan FIFO. |
| Stack | `stack<string> tumpukanAlert` | Menyimpan log alarm dari paket yang diblokir. Alert terbaru akan tampil paling atas sesuai prinsip LIFO. |
| Linked List | `NodeSesi* listSesiAktif` | Menyimpan paket yang lolos inspeksi atau `ALLOWED` sebagai sesi aktif. Penambahan data dilakukan secara dinamis. |
| Binary Search Tree | `NodeTree* databasePortBahaya` | Menyimpan port berbahaya seperti 21, 22, 23, 80, 445, dan 4444 beserta informasi ancamannya. |
| Graph | `map<string, vector<string>> topologiJaringan` | Memodelkan topologi jaringan kantor: Router, Firewall + Mini IDS, Core Switch, server, dan PC kantor. |
| BFS | `bfsJalurTercepat()` | Mencari jalur terpendek dari perangkat berisiko menuju `Database Server` sebagai aset kritis. |
| DFS | `dfsHitungBlastRadius()` | Menelusuri seluruh perangkat yang dapat dijangkau dari satu titik awal untuk simulasi blast radius. |
| Searching | `linearSearchArray()` dan `binarySearchArray()` | Membandingkan pencarian biasa dan pencarian biner pada blacklist domain/IP. |
| Sorting | `bubbleSortLogAlarm()` dan `quickSortLogAlarm()` | Mengurutkan paket blocked berdasarkan ukuran payload dari terbesar ke terkecil. |
| Vector | `vector<PaketData> logAlertData` | Menyimpan data paket blocked dalam bentuk terstruktur agar bisa digunakan oleh fitur Sorting. |
| Big O | Output kompleksitas pada menu BFS, DFS, Sorting, dan Searching | Menjelaskan efisiensi algoritma yang digunakan dalam program. |

## Penerapan Setiap Fitur dalam Program

### Menu [1] Tambah Paket Simulasi Trafik

Menu ini digunakan untuk membuat paket simulasi. Admin memilih perangkat asal trafik dari daftar PC kantor, lalu memasukkan target IP/domain, port tujuan, dan ukuran payload.

Data tersebut disimpan dalam `struct PaketData`, kemudian dimasukkan ke `queue<PaketData> antreanPaket`.

### Menu [2] Lihat Isi Antrean Paket

Menu ini menampilkan isi Queue tanpa menghapus data aslinya. Program menggunakan salinan Queue, sehingga antrean utama tetap aman dan tetap bisa diproses pada Menu `[3]`.

### Menu [3] Jalankan Inspeksi Firewall

Menu ini adalah inti program. Firewall + Mini IDS mengambil paket dari Queue secara FIFO, lalu melakukan dua pengecekan:

1. Mengecek target pada blacklist domain/IP.
2. Mengecek port pada Binary Search Tree port berbahaya.

Jika paket aman, data masuk ke Linked List sesi aktif. Jika paket berbahaya, data masuk ke Stack alert, disimpan ke Vector log, dan perangkat asal ditandai `BERISIKO`.

### Menu [4] Lihat Log Alarm Serangan

Menu ini menampilkan isi Stack alert. Karena Stack menggunakan prinsip LIFO, alert terbaru akan muncul lebih dahulu.

### Menu [5] Lihat Monitoring Sesi Aktif

Menu ini menampilkan Linked List sesi aktif, yaitu daftar koneksi yang mendapatkan keputusan `ALLOWED`.

### Menu [6] Lihat Topologi Jaringan

Menu ini menampilkan Graph topologi jaringan kantor beserta status setiap node. Status awal perangkat adalah `AMAN`, lalu berubah menjadi `BERISIKO` jika perangkat tersebut pernah mengirim paket yang diblokir.

### Menu [7] Deteksi Jalur Serangan ke Aset Kritis

Menu ini menjalankan BFS. Admin memilih titik awal, lalu program mencari jalur tercepat menuju `Database Server`.

Contoh:

```text
PC HRD -> Core Switch -> Database Server
```

### Menu [8] Analisis Blast Radius

Menu ini menjalankan DFS. Program menelusuri perangkat yang dapat dijangkau dari satu node awal. Fitur ini menggambarkan potensi dampak jika sebuah perangkat berisiko tidak segera diisolasi.

### Menu [9] Urutkan Log Alarm Berdasarkan Prioritas

Menu ini menggunakan data blocked yang tersimpan di Vector. Admin dapat memilih Bubble Sort atau Quick Sort untuk mengurutkan alarm berdasarkan payload terbesar.

### Menu [10] Bandingkan Linear vs Binary Search

Menu ini membandingkan dua teknik pencarian pada blacklist:

- Linear Search: mencari data satu per satu.
- Binary Search: mencari data pada array yang sudah diurutkan.

Program juga menampilkan jumlah perbandingan agar perbedaan efisiensinya terlihat.

## Fitur Utama

### 1. Smart Target Detection

Pengguna cukup memasukkan target tujuan. Program otomatis menentukan apakah input tersebut termasuk IP Address atau Domain.

```text
google.com -> DOMAIN
8.8.8.8    -> IP
```

### 2. Pemilihan Perangkat Asal Trafik

Perangkat asal trafik dibuat seperti jaringan kantor:

```text
[1] PC Admin
[2] PC HRD
[3] PC Karyawan 1
[4] PC Karyawan 2
```

Perangkat ini dipilih karena paling masuk akal sebagai sumber trafik keluar. Web Server dan Database Server tetap ada di topologi, tetapi diposisikan sebagai aset yang dilindungi.

### 3. Queue-Based Traffic Buffer

Paket yang masuk tidak langsung diproses, tetapi disimpan dulu di Queue. Prinsip yang digunakan adalah FIFO, yaitu paket pertama yang masuk akan diproses lebih dahulu.

### 4. Firewall Inspection

Firewall + Mini IDS melakukan dua pemeriksaan utama:

- blacklist IP/domain menggunakan Array dan Searching
- database port berbahaya menggunakan Binary Search Tree

Jika salah satu pemeriksaan mendeteksi ancaman, paket akan diblokir.

### 5. Active Session Monitoring

Paket yang aman akan dicatat sebagai sesi aktif menggunakan Linked List.

Setiap sesi menyimpan:

- perangkat asal
- tipe target
- target tujuan
- nomor port
- ukuran payload

### 6. Security Alert Logging

Paket yang diblokir akan masuk ke Stack sebagai log alarm.

Informasi yang dicatat:

- alasan blokir
- perangkat asal
- target tujuan
- tipe target
- port tujuan
- ukuran payload

### 7. Risk Marking

Jika sebuah PC mengirim paket berbahaya, status PC tersebut berubah:

```text
AMAN -> BERISIKO
```

Status tersebut dapat dilihat pada menu topologi jaringan.

### 8. BFS Attack Path Analysis

BFS digunakan untuk mencari jalur tercepat dari perangkat berisiko menuju Database Server.

Contoh:

```text
PC HRD -> Core Switch -> Database Server
Jumlah hop: 2
Kompleksitas: O(V + E)
```

### 9. DFS Blast Radius Analysis

DFS digunakan untuk menelusuri perangkat mana saja yang bisa dijangkau dari satu perangkat berisiko. Ini menggambarkan potensi dampak insiden apabila perangkat tersebut tidak segera diisolasi.

### 10. Alarm Prioritization

Log alarm dapat diurutkan berdasarkan ukuran payload. Payload terbesar dianggap lebih prioritas untuk dianalisis.

Algoritma yang tersedia:

- Bubble Sort
- Quick Sort

### 11. Searching Comparison

Program membandingkan dua algoritma pencarian:

- Linear Search
- Binary Search

Binary Search dilakukan setelah data blacklist diurutkan menggunakan Insertion Sort.

## Menu Program

```text
[1] Kirim / Masukkan Paket Baru (Simulasi Trafik)
[2] Lihat Isi Antrean Paket (Queue)
[3] Jalankan Inspeksi Firewall (Proses Antrean)
[4] Lihat Log Alarm Serangan (Stack/LIFO)
[5] Lihat Monitoring Sesi Aktif (Linked List)
[6] Lihat Topologi Jaringan (Graph)
[7] Deteksi Jalur Serangan ke Aset Kritis (BFS)
[8] Analisis Blast Radius / Dampak Insiden (DFS)
[9] Urutkan Log Alarm Berdasarkan Prioritas (Sorting)
[10] Bandingkan Linear vs Binary Search (Blacklist)
[0] Keluar Aplikasi
```

## Analisis Kompleksitas Big O

| Operasi | Kompleksitas |
|---|---|
| Queue Push | O(1) |
| Queue Traversal | O(n) |
| Firewall Inspection | O(n) |
| Linked List Insert | O(1) |
| Linked List Traversal | O(n) |
| BST Search | O(log n) rata-rata |
| BFS | O(V + E) |
| DFS | O(V + E) |
| Bubble Sort | O(n^2) |
| Quick Sort | O(n log n) rata-rata |
| Linear Search | O(n) |
| Binary Search | O(log n) |

Keterangan:

- `n` = jumlah data.
- `V` = jumlah vertex atau simpul.
- `E` = jumlah edge atau koneksi.

## Contoh Pengujian

### 1. Blokir Domain Berbahaya

Langkah:

1. Masuk Menu `[1]`.
2. Pilih `PC HRD`.
3. Masukkan target: `malware.com`.
4. Masukkan port: `443`.
5. Masukkan payload: `120`.
6. Jalankan Menu `[3]`.

Hasil:

```text
BLOCKED
Alasan: Akses Domain Terlarang
PC HRD ditandai BERISIKO
```

### 2. Blokir IP Blacklist

Langkah:

1. Masuk Menu `[1]`.
2. Pilih `PC Karyawan 1`.
3. Masukkan target: `1.1.1.1`.
4. Masukkan port: `443`.
5. Masukkan payload: `80`.
6. Jalankan Menu `[3]`.

Hasil:

```text
BLOCKED
Alasan: IP Tujuan Terdaftar di Blacklist Jaringan
PC Karyawan 1 ditandai BERISIKO
```

### 3. Blokir Port Kritis

Langkah:

1. Masuk Menu `[1]`.
2. Pilih `PC Karyawan 2`.
3. Masukkan target: `8.8.8.8`.
4. Masukkan port: `4444`.
5. Masukkan payload: `15`.
6. Jalankan Menu `[3]`.

Hasil:

```text
BLOCKED
Alasan: Deteksi Port Kritis/Unsecure -> Metasploit Default Reverse Shell Backdoor
```

### 4. Trafik Aman

Langkah:

1. Masuk Menu `[1]`.
2. Pilih `PC Admin`.
3. Masukkan target: `google.com`.
4. Masukkan port: `443`.
5. Masukkan payload: `50`.
6. Jalankan Menu `[3]`.

Hasil:

```text
ALLOWED
```

Lanjutkan ke Menu `[5]` untuk melihat sesi aktif.

### 5. Analisis BFS

Langkah:

1. Buat paket blocked dari `PC HRD`.
2. Jalankan inspeksi firewall.
3. Masuk Menu `[7]`.
4. Pilih `PC HRD` sebagai titik awal.

Hasil contoh:

```text
PC HRD -> Core Switch -> Database Server
Jumlah hop: 2
Kompleksitas: O(V + E)
```

### 6. Analisis DFS

Langkah:

1. Masuk Menu `[8]`.
2. Pilih perangkat yang berstatus BERISIKO.

Hasil:

Program menampilkan daftar perangkat yang dapat dijangkau dari titik awal tersebut sebagai simulasi blast radius.

### 7. Sorting Log Alarm

Langkah:

1. Buat beberapa paket blocked dengan payload berbeda.
2. Masuk Menu `[9]`.
3. Pilih Bubble Sort atau Quick Sort.

Hasil:

Program menampilkan prioritas alarm dari payload terbesar ke terkecil.

### 8. Searching Blacklist

Langkah:

1. Masuk Menu `[10]`.
2. Pilih Domain Blacklist atau IP Blacklist.
3. Masukkan target yang ingin dicari.

Hasil:

Program membandingkan jumlah perbandingan Linear Search dan Binary Search.

### 9. Simulasi Lengkap Incident Response

1. Kirim paket dari `PC HRD` menuju `phishing.net`.
2. Jalankan inspeksi firewall.
3. Firewall memblokir paket.
4. Alarm masuk ke Stack.
5. Status `PC HRD` berubah menjadi BERISIKO.
6. Lihat Graph untuk memastikan perubahan status.
7. Jalankan BFS untuk melihat jalur tercepat menuju Database Server.
8. Jalankan DFS untuk mengetahui perangkat yang berpotensi terdampak.
9. Jalankan Sorting untuk menentukan alarm prioritas.

## Kesimpulan

Mini Firewall & Intrusion Detection System (IDS) menunjukkan bagaimana konsep Struktur Data dan Algoritma dapat diintegrasikan ke dalam simulasi cyber security yang utuh. Queue digunakan sebagai buffer trafik, Array dan Binary Search Tree sebagai mekanisme inspeksi firewall, Linked List untuk sesi aktif, Stack untuk log alarm, dan Graph untuk memodelkan topologi jaringan kantor. BFS digunakan untuk mencari jalur tercepat menuju aset kritis, DFS digunakan untuk analisis blast radius, sedangkan Searching, Sorting, dan Big O digunakan untuk menunjukkan efisiensi algoritma.
