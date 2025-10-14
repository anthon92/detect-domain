#pragma once
#include <pcap.h>
#include <QString>
#include <QHostAddress>

class DomainSniffer {
public:
    explicit DomainSniffer();
    void start();

private:
    bool isVirtualOrPrivateAddress(const QHostAddress& addr);
    bool ensureNpcapInstalled();
    bool isNpcapInstalled();
    bool installNpcapSilently(const QString& installerPath);
    bool installNpcapInteractively(const QString& installerPath);

    void parseDNS(const u_char* data, int len);
    void parseTLS(const u_char* data, int len);
    static void packetHandler(u_char* user, const pcap_pkthdr* header, const u_char* packet);

    // Helper functions for detecting active interface
    QHostAddress localAddressForRoute(const QString& remoteIp = "8.8.8.8", quint16 remotePort = 53);
    QString findPcapDeviceForLocalIp(pcap_if_t* alldevs, const QHostAddress& localAddr);
    QString findFallbackPcapDevice(pcap_if_t* alldevs);
};
