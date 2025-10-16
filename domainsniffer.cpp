#include "domainsniffer.h"
#include <QDebug>
#include <QNetworkInterface>
#include <QHostAddress>
#include <cstring>
#include <QRegularExpression>

#ifdef _WIN32
#include <QCoreApplication>
#include <QFileInfo>
#include <QProcess>
#include <QThread>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#pragma pack(push, 1)
struct EthernetHeader {
    u_char dest[6];
    u_char src[6];
    u_short type;
};

struct IPHeader {
    u_char ver_ihl;
    u_char tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char ttl;
    u_char proto;
    u_short crc;
    u_char saddr[4];
    u_char daddr[4];
};

struct UDPHeader {
    u_short sport;
    u_short dport;
    u_short len;
    u_short crc;
};

struct TCPHeader {
    u_short sport;
    u_short dport;
    u_int seqnum;
    u_int acknum;
    u_char offset_reserved;
    u_char flags;
    u_short win;
    u_short crc;
    u_short urg;
};

struct DNSHeader {
    u_short id;
    u_short flags;
    u_short qcount;
    u_short ans;
    u_short auth;
    u_short add;
};
#pragma pack(pop)

DomainSniffer::DomainSniffer() {}

bool DomainSniffer::isVirtualOrPrivateAddress(const QHostAddress& addr) {
    if (addr.isNull()) return true;
    quint32 ip = addr.toIPv4Address();

    // RFC1918 private ranges
    if ((ip & 0xFF000000) == 0x0A000000) return true;        // 10.0.0.0/8
    if ((ip & 0xFFF00000) == 0xAC100000) return true;        // 172.16.0.0/12
    if ((ip & 0xFFFF0000) == 0xC0A80000) return true;        // 192.168.0.0/16
    if ((ip & 0xFFFF0000) == 0xC6120000) return true;        // 198.18.0.0/15 (test/lab)
    if ((ip & 0x000000FF) == 127) return true;               // 127.0.0.0/8 loopback

    // Common VMware NAT and Host-Only ranges
    if ((ip & 0xFFFF0000) == 0xC0A8E900) return true;        // 192.168.233.0/24 VMware
    if ((ip & 0xFFFF0000) == 0xC0A8EA00) return true;        // 192.168.234.0/24 VMware
    if ((ip & 0xFFFF0000) == 0xC0A8EB00) return true;        // 192.168.235.0/24 VMware

    // Common Hyper-V NAT / Default Switch
    if ((ip & 0xFFFFFF00) == 0xC0A8AA00) return true;        // 192.168.170.0/24 Hyper-V Default Switch

    // Common Wintun / VPN / virtual test ranges
    if ((ip & 0xFFFF0000) == 0xA9FE0000) return true;        // 169.254.0.0/16 (link-local)
    if ((ip & 0xFFFF0000) == 0x64400000) return true;        // 100.64.0.0/10 (Carrier-grade NAT, often VPN)
    if ((ip & 0xFFFF0000) == 0xC0A80100) return true;        // 192.168.1.0/24 (common local/VPN use)

    return false;
}

// =============================================================
// Detect active Internet interface
// =============================================================

QHostAddress DomainSniffer::localAddressForRoute(const QString& remoteIp, quint16 remotePort) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        qWarning() << "socket() failed for route detection";
        return QHostAddress();
    }

    struct sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(remotePort);
    inet_pton(AF_INET, remoteIp.toLocal8Bit().constData(), &remote.sin_addr);

    if (connect(sock, reinterpret_cast<struct sockaddr*>(&remote), sizeof(remote)) < 0) {
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        qWarning() << "connect() failed for route detection";
        return QHostAddress();
    }

    struct sockaddr_in local{};
    socklen_t len = sizeof(local);
    getsockname(sock, reinterpret_cast<struct sockaddr*>(&local), &len);

    char buf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &local.sin_addr, buf, sizeof(buf));

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    return QHostAddress(QString::fromUtf8(buf));
}

QString DomainSniffer::findPcapDeviceForLocalIp(pcap_if_t* alldevs, const QHostAddress& localAddr) {
    if (!alldevs) return QString();

    for (pcap_if_t* d = alldevs; d; d = d->next) {
        QString devName = QString::fromUtf8(d->name);
        QString devDesc = d->description ? d->description : "(no description)";
        // Skip unwanted virtual or non-physical adapters
        if (devName.contains("WAN", Qt::CaseInsensitive) ||
            devName.contains("Loopback", Qt::CaseInsensitive) ||
            devName.contains("tunnel", Qt::CaseInsensitive) ||
            devName.contains("Wintun", Qt::CaseInsensitive) ||
            devName.contains("VMware", Qt::CaseInsensitive) ||
            devName.contains("Hyper-V", Qt::CaseInsensitive) ||
            devName.contains("Virtual", Qt::CaseInsensitive))
            continue;
        if (devDesc.contains("WAN", Qt::CaseInsensitive) ||
            devDesc.contains("Loopback", Qt::CaseInsensitive) ||
            devDesc.contains("tunnel", Qt::CaseInsensitive) ||
            devDesc.contains("Wintun", Qt::CaseInsensitive) ||
            devDesc.contains("VMware", Qt::CaseInsensitive) ||
            devDesc.contains("Hyper-V", Qt::CaseInsensitive) ||
            devDesc.contains("Virtual", Qt::CaseInsensitive))
            continue;


        for (pcap_addr_t* a = d->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                struct sockaddr_in* sin = reinterpret_cast<struct sockaddr_in*>(a->addr);
                char buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
                QHostAddress devAddr(QString::fromUtf8(buf));
                if (devAddr == localAddr)
                    return devName;
            }
        }
    }
    return QString();
}

QString DomainSniffer::findFallbackPcapDevice(pcap_if_t* alldevs) {
    if (!alldevs) return QString();
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        QString devName = QString::fromUtf8(d->name);
        QString devDesc = d->description ? d->description : "(no description)";
        // Skip unwanted virtual or non-physical adapters
        if (devName.contains("WAN", Qt::CaseInsensitive) ||
            devName.contains("Loopback", Qt::CaseInsensitive) ||
            devName.contains("tunnel", Qt::CaseInsensitive) ||
            devName.contains("Wintun", Qt::CaseInsensitive) ||
            devName.contains("VMware", Qt::CaseInsensitive) ||
            devName.contains("Hyper-V", Qt::CaseInsensitive) ||
            devName.contains("Virtual", Qt::CaseInsensitive))
            continue;
        if (devDesc.contains("WAN", Qt::CaseInsensitive) ||
            devDesc.contains("Loopback", Qt::CaseInsensitive) ||
            devDesc.contains("tunnel", Qt::CaseInsensitive) ||
            devDesc.contains("Wintun", Qt::CaseInsensitive) ||
            devDesc.contains("VMware", Qt::CaseInsensitive) ||
            devDesc.contains("Hyper-V", Qt::CaseInsensitive) ||
            devDesc.contains("Virtual", Qt::CaseInsensitive))
            continue;

        for (pcap_addr_t* a = d->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET)
                return devName;
        }
    }
    return QString();
}

bool DomainSniffer::isNpcapInstalled() {
#ifdef _WIN32
    // Check registry key existence: HKLM\SOFTWARE\Npcap or SOFTWARE\\WOW6432Node\\Npcap
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Npcap", 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    } else {
        result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Npcap", 0, KEY_READ, &hKey);
        if (result == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
    }
    return false;
#elif defined(__APPLE__)
    // On macOS, libpcap is preinstalled with the system.
    // We just verify that the dynamic library is available.
    if (QFileInfo::exists("/usr/lib/libpcap.A.dylib") ||
        QFileInfo::exists("/usr/lib/libpcap.dylib")) {
        qDebug() << "libpcap detected (macOS system library).";
        return true;
    } else {
        qWarning() << "libpcap missing — opening Terminal to install via Homebrew.";
        QProcess::startDetached("open", { "-a", "Terminal", "/bin/bash", "-c", "brew install libpcap" });
        qCritical() << "libpcap not found. Please install it manually (e.g. via Homebrew: brew install libpcap)";
        return false;
    }
#else
    // Other Unix/Linux variants
    qDebug() << "Assuming libpcap available on this platform.";
    return true;
#endif
}


// =============================================================
// 🚀  Start packet capture
// =============================================================
void DomainSniffer::start() {
    if (!isNpcapInstalled()) {
        qCritical() << "Npcap isn't installed. Exiting...";
        return;
    }

    // ✅ Npcap is installed here — proceed normally
    qInfo() << "Npcap is installed. Starting packet capture...";

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        qCritical() << "Failed to initialize Winsock.";
        return;
    }
#endif

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        qCritical() << "Error finding devices:" << errbuf;
        return;
    }

    if (!alldevs) {
        qCritical() << "No network adapters found.";
        return;
    }

    qDebug() << "Available devices:";
    int i = 0;
    for (pcap_if_t* d = alldevs; d; d = d->next)
    {
        qDebug() << ++i << ":" << d->name << (d->description ? d->description : "(no description)");
    }

    // Detect the active Internet-connected interface
    QHostAddress local = localAddressForRoute();

    if (isVirtualOrPrivateAddress(local)) {
        qWarning() << "Detected address is virtual/private:" << local.toString();
        local = QHostAddress(); // Force fallback path
    }

    QString chosenDev;

    if (!local.isNull()) {
        qDebug() << "Detected local Internet address:" << local.toString();
        chosenDev = findPcapDeviceForLocalIp(alldevs, local);
        if (!chosenDev.isEmpty()) {
            qDebug() << "Matched device:" << chosenDev;
        } else {
            qDebug() << "No matching device for" << local.toString();
        }
    }

    if (chosenDev.isEmpty()) {
        chosenDev = findFallbackPcapDevice(alldevs);
        qDebug() << "Fallback device:" << chosenDev;
    }

    if (chosenDev.isEmpty()) {
        qCritical() << "No usable capture device found.";
        pcap_freealldevs(alldevs);
        return;
    }

    QByteArray devName = chosenDev.toLocal8Bit();
    const char* dev = devName.constData();

    qDebug() << "Using device:" << dev;

    pcap_t* handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
    if (!handle) {
        qCritical() << "Error opening device:" << errbuf;
        pcap_freealldevs(alldevs);
        return;
    }

    struct bpf_program fp;
    const char* filter_exp = "udp port 53 or tcp port 443";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        qCritical() << "Failed to set filter:" << pcap_geterr(handle);
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return;
    }

    qDebug() << "Listening for DNS + TLS traffic...";
    pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char*>(this));

    pcap_freealldevs(alldevs);
}

// =============================================================
// 🧩  Packet handler + parsers
// =============================================================

void DomainSniffer::packetHandler(u_char* user, const pcap_pkthdr* header, const u_char* packet) {
    auto* sniffer = reinterpret_cast<DomainSniffer*>(user);
    const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(packet);

    if (ntohs(eth->type) != 0x0800) return; // IPv4 only

    const IPHeader* ip = reinterpret_cast<const IPHeader*>(packet + sizeof(EthernetHeader));
    int ipHeaderLen = (ip->ver_ihl & 0x0F) * 4;

    const u_char* payload = packet + sizeof(EthernetHeader) + ipHeaderLen;

    if (ip->proto == 17) { // UDP (DNS)
        const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(payload);
        int udpHeaderLen = sizeof(UDPHeader);
        int dnsLen = ntohs(udp->len) - udpHeaderLen;
        const u_char* dnsData = payload + udpHeaderLen;
        sniffer->parseDNS(dnsData, dnsLen);
    } else if (ip->proto == 6) { // TCP (TLS)
        const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(payload);
        int tcpHeaderLen = ((tcp->offset_reserved >> 4) & 0xF) * 4;
        const u_char* tlsData = payload + tcpHeaderLen;
        int tlsLen = ntohs(ip->tlen) - ipHeaderLen - tcpHeaderLen;
        sniffer->parseTLS(tlsData, tlsLen);
    }
}

void DomainSniffer::parseDNS(const u_char* data, int len) {
    if (len < (int)sizeof(DNSHeader)) return;

    const DNSHeader* dns = reinterpret_cast<const DNSHeader*>(data);

    if (ntohs(dns->qcount) == 0) return;

    const u_char* p = data + sizeof(DNSHeader);
    QString domain;

    while (p < data + len) {
        int labelLen = *p++;
        if (labelLen == 0) break;
        if (p + labelLen > data + len) break;
        if (!domain.isEmpty()) domain.append('.');
        for (int i = 0; i < labelLen; ++i)
            domain.append(QChar(static_cast<char>(*p++)));
    }

    if (!domain.isEmpty())
        qDebug() << "🌐 DNS Query:" << domain;
}

void DomainSniffer::parseTLS(const u_char *data, int len) {
    if (len < 5) return;

    // Check TLS Record Layer
    if (data[0] != 0x16) return;  // 0x16 = Handshake
    if (data[1] != 0x03) return;  // TLS major version
    if (data[5] != 0x01) return;  // Handshake Type = ClientHello (0x01)

    int pos = 5; // Skip record header
    pos += 4;    // Skip Handshake header (type + length)
    if (pos + 34 > len) return;

    pos += 2 + 32; // Version (2) + Random (32)

    // Session ID
    if (pos + 1 > len) return;
    uint8_t sessionIDLen = data[pos];
    pos += 1 + sessionIDLen;
    if (pos > len) return;

    // Cipher Suites
    if (pos + 2 > len) return;
    uint16_t cipherLen = (data[pos] << 8) | data[pos + 1];
    pos += 2 + cipherLen;
    if (pos > len) return;

    // Compression Methods
    if (pos + 1 > len) return;
    uint8_t compLen = data[pos];
    pos += 1 + compLen;
    if (pos > len) return;

    // Extensions Length
    if (pos + 2 > len) return;
    uint16_t extLen = (data[pos] << 8) | data[pos + 1];
    pos += 2;

    int extEnd = pos + extLen;
    if (extEnd > len) return;

    // Iterate extensions
    while (pos + 4 <= extEnd) {
        uint16_t extType = (data[pos] << 8) | data[pos + 1];
        uint16_t extSize = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;
        if (pos + extSize > extEnd) break;

        if (extType == 0x00) {  // SNI Extension
            int sniPos = pos + 2; // Skip list length
            if (sniPos + 3 > extEnd) break;

            uint8_t sniType = data[sniPos];
            uint16_t sniLen = (data[sniPos + 1] << 8) | data[sniPos + 2];
            sniPos += 3;

            if (sniPos + sniLen > extEnd) break;

            QString sni;
            for (int i = 0; i < sniLen; ++i) {
                char c = data[sniPos + i];
                if (isprint(static_cast<unsigned char>(c)))
                    sni.append(c);
            }

            if (!sni.isEmpty())
                qInfo() << "🌐 TLS SNI:" << sni;
            break;
        }

        pos += extSize;
    }
}

