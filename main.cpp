#include "domainsniffer.h"
#include <QCoreApplication>

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);

    DomainSniffer sniffer;
    sniffer.start();

    return app.exec();
}
