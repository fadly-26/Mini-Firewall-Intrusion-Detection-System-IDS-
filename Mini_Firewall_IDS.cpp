// ===============================================================
// MINI FIREWALL & INTRUSION DETECTION SYSTEM (IDS)
// ---------------------------------------------------------------
// Mata Kuliah : Struktur Data dan Algoritma
// Bahasa      : C++
// Deskripsi   : Simulasi sistem keamanan jaringan berbasis terminal
//               yang menerapkan Array, Queue, Stack, Linked List,
//               Binary Search Tree, Graph, BFS, DFS, Searching,
//               Sorting, dan analisis Big O.
// ===============================================================

#include <iostream>
#include <string>
#include <queue>
#include <stack>
#include <vector>
#include <map>
#include <cctype>
using namespace std;

// ===============================================================
// TIPE DATA DAN VARIABEL
// Struct PaketData merepresentasikan satu paket trafik jaringan.
// hostAsalJaringan menghubungkan modul firewall dengan topologi graph,
// sehingga perangkat yang menghasilkan trafik berbahaya dapat dianalisis
// lebih lanjut memakai BFS dan DFS.
// ===============================================================
struct PaketData {
    string hostAsalJaringan;
    string tipeTarget;
    string targetTujuan;
    int portTujuan;
    int ukuranPayload;
};

// ===============================================================
// LINKED LIST UNTUK SESI AKTIF
// NodeSesi menyimpan koneksi yang diizinkan oleh firewall.
// Struktur linked list dipilih karena jumlah sesi dapat bertambah
// secara dinamis selama program berjalan.
// ===============================================================
struct NodeSesi {
    string hostAsalAktif;
    string tipeTargetAktif;
    string targetAktif;
    int portAktif;
    int ukuranPayloadAktif;
    NodeSesi* next;
};

// ===============================================================
// BINARY SEARCH TREE UNTUK DATABASE PORT BERBAHAYA
// Setiap node menyimpan nomor port dan informasi ancaman.
// BST mempercepat pencarian port berbahaya dibandingkan pengecekan
// satu per satu pada data yang jumlahnya besar.
// ===============================================================
struct NodeTree {
    int portBahaya;
    string infoSerangan;
    NodeTree* left;
    NodeTree* right;
};

string deteksiTipeTarget(string target) {
    for (char c : target) {
        if (isalpha(c)) return "DOMAIN";
    }
    return "IP";
}

void tambahSesi(NodeSesi*& head, string hostAsal, string tipe, string target, int port, int payload) {
    NodeSesi* nodeBaru = new NodeSesi;
    nodeBaru->hostAsalAktif = hostAsal;
    nodeBaru->tipeTargetAktif = tipe;
    nodeBaru->targetAktif = target;
    nodeBaru->portAktif = port;
    nodeBaru->ukuranPayloadAktif = payload;
    nodeBaru->next = head;
    head = nodeBaru;
}

void cetakSesiAktif(NodeSesi* head) {
    cout << "\n==================================================\n";
    cout << ">>> MONITORING SESI AKTIF (LINKED LIST) <<<\n";
    cout << "==================================================\n";

    if (head == nullptr) {
        cout << "[Kosong] Belum ada sesi koneksi yang aktif di jaringan.\n";
        return;
    }

    NodeSesi* temp = head;
    int counter = 1;
    while (temp != nullptr) {
        cout << "Sesi #" << counter++ << " [Connected]\n";
        cout << "  [+] Perangkat Asal   : " << temp->hostAsalAktif << "\n";
        cout << "  [+] Tipe Data Target : " << temp->tipeTargetAktif << "\n";
        cout << "  [+] Target / Tujuan  : " << temp->targetAktif << "\n";
        cout << "  [+] Port Terbuka     : " << temp->portAktif << "\n";
        cout << "  [+] Ukuran Payload   : " << temp->ukuranPayloadAktif << " KB\n";
        cout << "  --------------------------------------------------\n";
        temp = temp->next;
    }
}

void bebaskanSesi(NodeSesi* head) {
    while (head != nullptr) {
        NodeSesi* temp = head;
        head = head->next;
        delete temp;
    }
}

NodeTree* insertTree(NodeTree* root, int port, string info) {
    if (root == nullptr) {
        return new NodeTree{port, info, nullptr, nullptr};
    }
    if (port < root->portBahaya) {
        root->left = insertTree(root->left, port, info);
    } else if (port > root->portBahaya) {
        root->right = insertTree(root->right, port, info);
    }
    return root;
}

NodeTree* cariPortBahaya(NodeTree* root, int port) {
    if (root == nullptr || root->portBahaya == port) return root;
    if (port < root->portBahaya) return cariPortBahaya(root->left, port);
    return cariPortBahaya(root->right, port);
}

void bebaskanTree(NodeTree* root) {
    if (root == nullptr) return;
    bebaskanTree(root->left);
    bebaskanTree(root->right);
    delete root;
}

void tampilAntreanQueue(queue<PaketData> antrean) {
    cout << "\n==================================================\n";
    cout << ">>> BUFFER ANTREAN PAKET JARINGAN (QUEUE) <<<\n";
    cout << "==================================================\n";

    if (antrean.empty()) {
        cout << "[Kosong] Tidak ada paket dalam antrean saat ini.\n";
        return;
    }

    cout << "Total paket mengantri : " << antrean.size() << " paket\n";
    cout << "--------------------------------------------------\n";

    int urutan = 1;
    while (!antrean.empty()) {
        PaketData p = antrean.front();
        antrean.pop();

        cout << "Antrian #" << urutan++ << " [Menunggu Inspeksi]\n";
        cout << "  [>] Perangkat Asal : " << p.hostAsalJaringan << "\n";
        cout << "  [>] Tipe Target    : " << p.tipeTarget << "\n";
        cout << "  [>] Target         : " << p.targetTujuan << "\n";
        cout << "  [>] Port           : " << p.portTujuan << "\n";
        cout << "  [>] Payload        : " << p.ukuranPayload << " KB\n";
        cout << "  --------------------------------------------------\n";
    }
    cout << "[Paket terdepan akan diproses pertama sesuai prinsip FIFO]\n";
}

// ===============================================================
// GRAPH UNTUK TOPOLOGI JARINGAN
// Topologi dibuat sesuai README:
// Internet - Router - Firewall - Core Switch
// Core Switch bercabang ke Server Switch dan Office Switch.
// ===============================================================
void tambahKoneksi(map<string, vector<string>>& adjList, string a, string b) {
    adjList[a].push_back(b);
    adjList[b].push_back(a);
}

void bangunTopologiJaringan(map<string, vector<string>>& adjList,
                             map<string, string>& statusNode,
                             vector<string>& daftarPerangkat) {
    daftarPerangkat = {
        "Internet",
        "Router",
        "Firewall + Mini IDS",
        "Core Switch",
        "Server Switch",
        "Office Switch",
        "Server",
        "PC Admin",
        "PC HRD",
        "PC Karyawan"
    };

    for (string perangkat : daftarPerangkat) {
        statusNode[perangkat] = "AMAN";
        adjList[perangkat];
    }

    // Urutan koneksi sengaja disusun agar demo DFS lebih mudah dibaca:
    // dari PC kantor, DFS mengecek area Office lebih dulu, lanjut ke Server,
    // lalu naik ke Firewall, Router, dan Internet.
    tambahKoneksi(adjList, "Office Switch", "PC Admin");
    tambahKoneksi(adjList, "Office Switch", "PC HRD");
    tambahKoneksi(adjList, "Office Switch", "PC Karyawan");
    tambahKoneksi(adjList, "Core Switch", "Office Switch");
    tambahKoneksi(adjList, "Core Switch", "Server Switch");
    tambahKoneksi(adjList, "Server Switch", "Server");
    tambahKoneksi(adjList, "Core Switch", "Firewall + Mini IDS");
    tambahKoneksi(adjList, "Firewall + Mini IDS", "Router");
    tambahKoneksi(adjList, "Router", "Internet");
}

void tampilkanDaftarPerangkatBernomor(vector<string>& daftarPerangkat,
                                       map<string, string>& statusNode) {
    for (size_t i = 0; i < daftarPerangkat.size(); i++) {
        cout << "[" << (i + 1) << "] " << daftarPerangkat[i]
             << "  (Status: " << statusNode[daftarPerangkat[i]] << ")\n";
    }
}

void tampilkanDaftarPerangkatAsal(vector<string>& daftarPerangkatAsal,
                                   map<string, string>& statusNode) {
    for (size_t i = 0; i < daftarPerangkatAsal.size(); i++) {
        cout << "[" << (i + 1) << "] " << daftarPerangkatAsal[i]
             << "  (Status: " << statusNode[daftarPerangkatAsal[i]] << ")\n";
    }
}

void tampilVisualTopologi() {
    cout << "\n                     Internet\n";
    cout << "                         |\n";
    cout << "                    +----------+\n";
    cout << "                    | Router   |\n";
    cout << "                    +----------+\n";
    cout << "                         |\n";
    cout << "              +----------------------+\n";
    cout << "              | Firewall + Mini IDS  |\n";
    cout << "              +----------------------+\n";
    cout << "                         |\n";
    cout << "                  +---------------+\n";
    cout << "                  | Core Switch   |\n";
    cout << "                  +---------------+\n";
    cout << "                    /           \\\n";
    cout << "                   /             \\\n";
    cout << "         +---------------+   +---------------+\n";
    cout << "         | Server Switch |   | Office Switch |\n";
    cout << "         +---------------+   +---------------+\n";
    cout << "                 |             /     |      \\\n";
    cout << "                 |            /      |       \\\n";
    cout << "              Server    PC Admin  PC HRD  PC Karyawan\n";
}

void tampilTopologiJaringan(map<string, vector<string>>& adjList,
                             map<string, string>& statusNode,
                             vector<string>& daftarPerangkat) {
    cout << "\n==================================================\n";
    cout << ">>> TOPOLOGI JARINGAN (GRAPH) <<<\n";
    cout << "==================================================\n";

    tampilVisualTopologi();

    cout << "\nDaftar adjacency list:\n";
    cout << "--------------------------------------------------\n";
    for (string node : daftarPerangkat) {
        cout << "- " << node << " [" << statusNode[node] << "]\n";
        cout << "    Terhubung ke : ";

        vector<string>& tetangga = adjList[node];
        for (size_t i = 0; i < tetangga.size(); i++) {
            cout << tetangga[i];
            if (i + 1 < tetangga.size()) cout << ", ";
        }
        cout << "\n";
    }

    cout << "--------------------------------------------------\n";
    cout << "[Info] Total simpul (V) = " << daftarPerangkat.size() << "\n";
    cout << "[Info] Graph bersifat undirected, sehingga koneksi dapat dibaca dua arah.\n";
}

// ===============================================================
// BFS UNTUK JALUR TERCEPAT KE SERVER
// BFS menjelajah graph level demi level memakai queue.
// Pada program ini BFS mencari jalur hop paling sedikit dari
// perangkat berisiko menuju Server sebagai aset penting.
// ===============================================================
vector<string> bfsJalurTercepat(map<string, vector<string>>& adjList,
                                 string nodeAwal,
                                 string nodeTujuan,
                                 vector<string>& urutanKunjungan) {
    queue<string> antrianBFS;
    map<string, bool> sudahDikunjungi;
    map<string, string> asalSimpul;

    antrianBFS.push(nodeAwal);
    sudahDikunjungi[nodeAwal] = true;
    urutanKunjungan.push_back(nodeAwal);
    bool ketemu = (nodeAwal == nodeTujuan);

    while (!antrianBFS.empty() && !ketemu) {
        string sekarang = antrianBFS.front();
        antrianBFS.pop();

        for (string tetangga : adjList[sekarang]) {
            if (!sudahDikunjungi[tetangga]) {
                sudahDikunjungi[tetangga] = true;
                asalSimpul[tetangga] = sekarang;
                urutanKunjungan.push_back(tetangga);

                if (tetangga == nodeTujuan) {
                    ketemu = true;
                    break;
                }

                antrianBFS.push(tetangga);
            }
        }
    }

    vector<string> jalur;
    if (!ketemu) return jalur;

    string node = nodeTujuan;
    while (node != nodeAwal) {
        jalur.push_back(node);
        node = asalSimpul[node];
    }
    jalur.push_back(nodeAwal);

    for (int i = 0, j = (int)jalur.size() - 1; i < j; i++, j--) {
        string temp = jalur[i];
        jalur[i] = jalur[j];
        jalur[j] = temp;
    }

    return jalur;
}

// ===============================================================
// DFS UNTUK ANALISIS BLAST RADIUS
// DFS menelusuri graph sedalam mungkin terlebih dahulu.
// Hasil DFS adalah jangkauan konektivitas, bukan bukti bahwa
// semua node pasti terinfeksi.
// ===============================================================
void dfsJelajahi(map<string, vector<string>>& adjList,
                  string node,
                  map<string, bool>& sudahDikunjungi,
                  vector<string>& hasilJelajah) {
    sudahDikunjungi[node] = true;
    hasilJelajah.push_back(node);

    for (string tetangga : adjList[node]) {
        if (!sudahDikunjungi[tetangga]) {
            dfsJelajahi(adjList, tetangga, sudahDikunjungi, hasilJelajah);
        }
    }
}

vector<string> dfsHitungBlastRadius(map<string, vector<string>>& adjList, string nodeAwal) {
    map<string, bool> sudahDikunjungi;
    vector<string> hasilJelajah;
    dfsJelajahi(adjList, nodeAwal, sudahDikunjungi, hasilJelajah);
    return hasilJelajah;
}

void bubbleSortLogAlarm(vector<PaketData>& data, long long& jumlahOperasi) {
    int n = (int)data.size();
    jumlahOperasi = 0;

    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - 1 - i; j++) {
            jumlahOperasi++;
            if (data[j].ukuranPayload < data[j + 1].ukuranPayload) {
                PaketData temp = data[j];
                data[j] = data[j + 1];
                data[j + 1] = temp;
            }
        }
    }
}

int partisiLogAlarm(vector<PaketData>& data, int low, int high, long long& jumlahOperasi) {
    int pivot = data[high].ukuranPayload;
    int i = low - 1;

    for (int j = low; j < high; j++) {
        jumlahOperasi++;
        if (data[j].ukuranPayload > pivot) {
            i++;
            PaketData temp = data[i];
            data[i] = data[j];
            data[j] = temp;
        }
    }

    PaketData temp = data[i + 1];
    data[i + 1] = data[high];
    data[high] = temp;
    return i + 1;
}

void quickSortLogAlarm(vector<PaketData>& data, int low, int high, long long& jumlahOperasi) {
    if (low < high) {
        int posPivot = partisiLogAlarm(data, low, high, jumlahOperasi);
        quickSortLogAlarm(data, low, posPivot - 1, jumlahOperasi);
        quickSortLogAlarm(data, posPivot + 1, high, jumlahOperasi);
    }
}

int linearSearchArray(string arr[], int n, string target, long long& jumlahBanding) {
    jumlahBanding = 0;
    for (int i = 0; i < n; i++) {
        jumlahBanding++;
        if (arr[i] == target) return i;
    }
    return -1;
}

void insertionSortArray(string arr[], int n) {
    for (int i = 1; i < n; i++) {
        string kunci = arr[i];
        int j = i - 1;

        while (j >= 0 && arr[j] > kunci) {
            arr[j + 1] = arr[j];
            j--;
        }

        arr[j + 1] = kunci;
    }
}

int binarySearchArray(string arr[], int n, string target, long long& jumlahBanding) {
    jumlahBanding = 0;
    int low = 0;
    int high = n - 1;

    while (low <= high) {
        jumlahBanding++;
        int mid = (low + high) / 2;

        if (arr[mid] == target) return mid;
        if (arr[mid] < target) low = mid + 1;
        else high = mid - 1;
    }

    return -1;
}

void cetakRute(vector<string> data) {
    for (size_t i = 0; i < data.size(); i++) {
        cout << data[i];
        if (i + 1 < data.size()) cout << " -> ";
    }
}

int main() {
    string domainBlacklist[3] = {"malware.com", "phishing.net", "ads-tracker.org"};
    string ipBlacklist[3] = {"1.1.1.1", "2.2.2.2", "66.66.66.66"};
    int jmlBlacklist = 3;

    NodeTree* databasePortBahaya = nullptr;
    databasePortBahaya = insertTree(databasePortBahaya, 21, "FTP Plaintext (Raw Password Sniffing)");
    databasePortBahaya = insertTree(databasePortBahaya, 22, "SSH Remote Access (Brute Force Target)");
    databasePortBahaya = insertTree(databasePortBahaya, 23, "Telnet Unsecure (No Encryption)");
    databasePortBahaya = insertTree(databasePortBahaya, 80, "HTTP Cleartext (Vulnerable to MITM)");
    databasePortBahaya = insertTree(databasePortBahaya, 445, "SMB Port (Ransomware WannaCry/EternalBlue)");
    databasePortBahaya = insertTree(databasePortBahaya, 4444, "Metasploit Default Reverse Shell Backdoor");

    NodeSesi* listSesiAktif = nullptr;
    queue<PaketData> antreanPaket;
    stack<string> tumpukanAlert;
    vector<PaketData> logAlertData;

    map<string, vector<string>> topologiJaringan;
    map<string, string> statusNode;
    vector<string> daftarPerangkat;
    vector<string> daftarPerangkatAsal = {
        "PC Admin",
        "PC HRD",
        "PC Karyawan"
    };
    bangunTopologiJaringan(topologiJaringan, statusNode, daftarPerangkat);

    int pilihan;
    do {
        cout << "\n==================================================\n";
        cout << "     DASHBOARD KONTROL MINI-FIREWALL & IDS        \n";
        cout << "==================================================\n";
        cout << "[1] Kirim / Masukkan Paket Baru (Simulasi Trafik)\n";
        cout << "[2] Lihat Isi Antrean Paket (Queue)\n";
        cout << "[3] Jalankan Inspeksi Firewall (Proses Antrean)\n";
        cout << "[4] Lihat Log Alarm Serangan (Stack/LIFO)\n";
        cout << "[5] Lihat Monitoring Sesi Aktif (Linked List)\n";
        cout << "[6] Lihat Topologi Jaringan (Graph)\n";
        cout << "[7] Deteksi Jalur Serangan ke Server (BFS)\n";
        cout << "[8] Analisis Blast Radius / Dampak Insiden (DFS)\n";
        cout << "[9] Urutkan Log Alarm Berdasarkan Prioritas (Sorting)\n";
        cout << "[10] Bandingkan Linear vs Binary Search (Blacklist)\n";
        cout << "[0] Keluar Aplikasi\n";
        cout << "--------------------------------------------------\n";
        cout << "Pilih Menu: ";
        cin >> pilihan;

        switch (pilihan) {
            case 1: {
                PaketData paketBaru;
                cout << "\n--- SIMULASI PAKET MASUK ---\n";
                cout << "Daftar Perangkat Asal Trafik:\n";
                tampilkanDaftarPerangkatAsal(daftarPerangkatAsal, statusNode);

                cout << "Pilih Perangkat Asal (nomor)  : ";
                int nomorAsal;
                cin >> nomorAsal;

                if (nomorAsal < 1 || nomorAsal > (int)daftarPerangkatAsal.size()) {
                    cout << "\nNomor perangkat tidak valid!\n";
                    break;
                }

                paketBaru.hostAsalJaringan = daftarPerangkatAsal[nomorAsal - 1];

                cout << "Masukkan Target (IP / Domain) : ";
                cin >> paketBaru.targetTujuan;
                paketBaru.tipeTarget = deteksiTipeTarget(paketBaru.targetTujuan);
                cout << "Masukkan Nomor Port Tujuan    : ";
                cin >> paketBaru.portTujuan;
                cout << "Masukkan Ukuran Payload (KB)  : ";
                cin >> paketBaru.ukuranPayload;

                antreanPaket.push(paketBaru);

                cout << "-> [System] Otomatis mendeteksi tipe target sebagai: "
                     << paketBaru.tipeTarget << "\n";
                cout << ">> Sukses: Paket masuk ke Buffer Antrean Jaringan.\n";
                cout << ">> Total paket dalam antrean sekarang: " << antreanPaket.size() << "\n";
                break;
            }

            case 2:
                tampilAntreanQueue(antreanPaket);
                break;

            case 3: {
                cout << "\n--- MEMULAI INSPEKSI FIREWALL ENGINE ---\n";
                if (antreanPaket.empty()) {
                    cout << "[Info] Tidak ada paket di dalam antrean (Queue) untuk diperiksa.\n";
                    break;
                }

                int counter = 1;
                while (!antreanPaket.empty()) {
                    PaketData p = antreanPaket.front();
                    antreanPaket.pop();

                    cout << "\nChecking Paket ke-" << counter++
                         << " (dari " << p.hostAsalJaringan << ")...\n";

                    bool isBlocked = false;
                    string alasanBlokir = "";

                    if (p.tipeTarget == "DOMAIN") {
                        for (int i = 0; i < jmlBlacklist; i++) {
                            if (p.targetTujuan == domainBlacklist[i]) {
                                isBlocked = true;
                                alasanBlokir = "Akses Domain Terlarang (" + p.targetTujuan + ")";
                                break;
                            }
                        }
                    } else if (p.tipeTarget == "IP") {
                        for (int i = 0; i < jmlBlacklist; i++) {
                            if (p.targetTujuan == ipBlacklist[i]) {
                                isBlocked = true;
                                alasanBlokir = "IP Tujuan Terdaftar di Blacklist Jaringan (" + p.targetTujuan + ")";
                                break;
                            }
                        }
                    }

                    NodeTree* hasilCekTree = cariPortBahaya(databasePortBahaya, p.portTujuan);
                    if (hasilCekTree != nullptr) {
                        if (alasanBlokir != "") alasanBlokir += " + ";
                        alasanBlokir += "Deteksi Port Kritis/Unsecure -> " + hasilCekTree->infoSerangan;
                        isBlocked = true;
                    }

                    if (isBlocked) {
                        cout << "[!!] HASIL: BLOCKED! Paket dibuang demi keamanan.\n";

                        string detailAlert = "ALERT CRITICAL!\n"
                                             "  [-] Alasan Blokir : " + alasanBlokir + "\n"
                                             "  [-] Perangkat Asal: " + p.hostAsalJaringan + "\n"
                                             "  [-] Tipe Target   : " + p.tipeTarget + "\n"
                                             "  [-] Target Tujuan : " + p.targetTujuan + "\n"
                                             "  [-] Port Dituju   : " + to_string(p.portTujuan) + "\n"
                                             "  [-] Ukuran Payload: " + to_string(p.ukuranPayload) + " KB\n"
                                             "  --------------------------------------------------";

                        tumpukanAlert.push(detailAlert);
                        logAlertData.push_back(p);

                        if (statusNode.count(p.hostAsalJaringan)) {
                            statusNode[p.hostAsalJaringan] = "BERISIKO";
                            cout << "[!!] Perangkat '" << p.hostAsalJaringan
                                 << "' ditandai BERISIKO pada topologi jaringan.\n";
                            cout << "     -> Cek Menu [7] BFS / [8] DFS untuk analisis lanjutan.\n";
                        }
                    } else {
                        cout << "[+] HASIL: ALLOWED! Paket aman.\n";
                        tambahSesi(listSesiAktif, p.hostAsalJaringan, p.tipeTarget,
                                   p.targetTujuan, p.portTujuan, p.ukuranPayload);
                    }
                }

                cout << "\n>> Proses Inspeksi Selesai. Seluruh antrean bersih.\n";
                break;
            }

            case 4: {
                cout << "\n==================================================\n";
                cout << "    LOG ALARM SECURITY OPERATION CENTER (SOC)     \n";
                cout << "==================================================\n";

                if (tumpukanAlert.empty()) {
                    cout << "[Aman] Belum ada alarm serangan saat ini.\n";
                    break;
                }

                cout << "Menampilkan riwayat ancaman terbaru (Prinsip STACK - LIFO):\n\n";
                stack<string> tempStack = tumpukanAlert;
                while (!tempStack.empty()) {
                    cout << tempStack.top() << "\n";
                    tempStack.pop();
                }
                break;
            }

            case 5:
                cetakSesiAktif(listSesiAktif);
                break;

            case 6:
                tampilTopologiJaringan(topologiJaringan, statusNode, daftarPerangkat);
                break;

            case 7: {
                cout << "\n==================================================\n";
                cout << ">>> BFS: JALUR TERCEPAT KE SERVER <<<\n";
                cout << "==================================================\n";
                tampilkanDaftarPerangkatBernomor(daftarPerangkat, statusNode);

                cout << "Pilih perangkat yang dicurigai sebagai titik awal (nomor): ";
                int nomorAwal;
                cin >> nomorAwal;

                if (nomorAwal < 1 || nomorAwal > (int)daftarPerangkat.size()) {
                    cout << "\nNomor tidak valid!\n";
                    break;
                }

                string nodeAwal = daftarPerangkat[nomorAwal - 1];
                string asetKritis = "Server";
                vector<string> urutanBFS;
                vector<string> jalur = bfsJalurTercepat(topologiJaringan, nodeAwal, asetKritis, urutanBFS);

                cout << "\n>> Urutan kunjungan BFS:\n   ";
                cetakRute(urutanBFS);

                if (jalur.empty()) {
                    cout << "\n\n[Info] Tidak ditemukan jalur dari "
                         << nodeAwal << " menuju " << asetKritis << ".\n";
                } else {
                    cout << "\n\n>> Jalur tercepat dari "
                         << nodeAwal << " ke " << asetKritis << ":\n   ";
                    cetakRute(jalur);

                    cout << "\n>> Jumlah hop     : " << (jalur.size() - 1) << "\n";
                    cout << ">> Kompleksitas   : O(V + E) [Big-O BFS]\n";
                    cout << ">> Makna          : BFS menunjukkan rute terpendek menuju aset penting.\n";
                }
                break;
            }

            case 8: {
                cout << "\n==================================================\n";
                cout << ">>> DFS: ANALISIS BLAST RADIUS <<<\n";
                cout << "==================================================\n";
                tampilkanDaftarPerangkatBernomor(daftarPerangkat, statusNode);

                cout << "Pilih perangkat yang sudah terindikasi berisiko (nomor): ";
                int nomorAwal;
                cin >> nomorAwal;

                if (nomorAwal < 1 || nomorAwal > (int)daftarPerangkat.size()) {
                    cout << "\nNomor tidak valid!\n";
                    break;
                }

                string nodeAwal = daftarPerangkat[nomorAwal - 1];
                vector<string> hasilJelajah = dfsHitungBlastRadius(topologiJaringan, nodeAwal);

                cout << "\n>> Urutan penjelajahan DFS mulai dari " << nodeAwal << ":\n   ";
                cetakRute(hasilJelajah);

                cout << "\n>> Jumlah node dalam jangkauan konektivitas : "
                     << (hasilJelajah.size() - 1)
                     << " node (di luar " << nodeAwal << " sendiri)\n";
                cout << ">> Kompleksitas   : O(V + E) [Big-O DFS]\n";
                cout << ">> Catatan        : Hasil DFS bukan berarti semua node pasti terinfeksi.\n";
                cout << "                   Hasil ini menunjukkan area yang perlu dipantau/diperiksa.\n";
                break;
            }

            case 9: {
                cout << "\n==================================================\n";
                cout << ">>> SORTING: PRIORITAS LOG ALARM <<<\n";
                cout << "==================================================\n";

                if (logAlertData.empty()) {
                    cout << "[Info] Belum ada data log alarm (paket blocked) untuk diurutkan.\n";
                    break;
                }

                cout << "Pilih Algoritma Sorting:\n";
                cout << "[1] Bubble Sort  (Big-O: O(n^2))\n";
                cout << "[2] Quick Sort   (Big-O: O(n log n) rata-rata)\n";
                cout << "Pilihan: ";

                int pilihanSort;
                cin >> pilihanSort;

                vector<PaketData> dataUrut = logAlertData;
                long long jumlahOperasi = 0;

                if (pilihanSort == 1) {
                    bubbleSortLogAlarm(dataUrut, jumlahOperasi);
                    cout << "\n>> Diurutkan dengan Bubble Sort (payload terbesar -> terkecil)\n";
                } else if (pilihanSort == 2) {
                    quickSortLogAlarm(dataUrut, 0, (int)dataUrut.size() - 1, jumlahOperasi);
                    cout << "\n>> Diurutkan dengan Quick Sort (payload terbesar -> terkecil)\n";
                } else {
                    cout << "\nPilihan tidak valid!\n";
                    break;
                }

                cout << "--------------------------------------------------\n";
                for (size_t i = 0; i < dataUrut.size(); i++) {
                    cout << "Prioritas #" << (i + 1)
                         << " | Asal: " << dataUrut[i].hostAsalJaringan
                         << " | Target: " << dataUrut[i].targetTujuan
                         << " | Payload: " << dataUrut[i].ukuranPayload << " KB\n";
                }

                cout << "--------------------------------------------------\n";
                cout << "[Big-O] Jumlah operasi perbandingan/penukaran: "
                     << jumlahOperasi << " (n = " << dataUrut.size() << ")\n";
                break;
            }

            case 10: {
                cout << "\n==================================================\n";
                cout << ">>> SEARCHING: LINEAR VS BINARY SEARCH <<<\n";
                cout << "==================================================\n";
                cout << "Cari di daftar mana?\n";
                cout << "[1] Domain Blacklist\n";
                cout << "[2] IP Blacklist\n";
                cout << "Pilihan: ";

                int pilihanArr;
                cin >> pilihanArr;

                string arrAsli[3];
                if (pilihanArr == 1) {
                    for (int i = 0; i < 3; i++) arrAsli[i] = domainBlacklist[i];
                } else if (pilihanArr == 2) {
                    for (int i = 0; i < 3; i++) arrAsli[i] = ipBlacklist[i];
                } else {
                    cout << "\nPilihan tidak valid!\n";
                    break;
                }

                cout << "Masukkan target yang dicari    : ";
                string target;
                cin >> target;

                long long bandingLinear = 0;
                long long bandingBinary = 0;
                int hasilLinear = linearSearchArray(arrAsli, 3, target, bandingLinear);

                string arrTerurut[3];
                for (int i = 0; i < 3; i++) arrTerurut[i] = arrAsli[i];
                insertionSortArray(arrTerurut, 3);

                int hasilBinary = binarySearchArray(arrTerurut, 3, target, bandingBinary);

                cout << "\n================== HASIL PENCARIAN ==================\n";
                cout << "[Linear Search] "
                     << (hasilLinear != -1 ? "Ditemukan di index " + to_string(hasilLinear) : "Tidak ditemukan")
                     << " | Perbandingan: " << bandingLinear
                     << " | Big-O: O(n)\n";

                cout << "[Binary Search ] "
                     << (hasilBinary != -1 ? "Ditemukan di index " + to_string(hasilBinary) + " (array terurut)" : "Tidak ditemukan")
                     << " | Perbandingan: " << bandingBinary
                     << " | Big-O: O(log n)\n";

                cout << "------------------------------------------------------\n";
                cout << "Catatan: dataset contoh ini kecil (n=3), tetapi Binary Search\n";
                cout << "akan lebih terasa keunggulannya saat blacklist berisi banyak data.\n";
                break;
            }

            case 0:
                cout << "\nMematikan Firewall Engine...\n";
                break;

            default:
                cout << "\nPilihan tidak valid!\n";
        }
    } while (pilihan != 0);

    bebaskanSesi(listSesiAktif);
    bebaskanTree(databasePortBahaya);

    cout << "[System] Memori berhasil dibebaskan. Program selesai.\n";
    return 0;
}
