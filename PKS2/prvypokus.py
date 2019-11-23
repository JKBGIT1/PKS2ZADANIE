from scapy.all import *

ETHERNET_START_SOURCE_MAC = 6
ETHERNET_WITHOUT_LENGTH = 12
ETHERNET_HEADER = 14
IPV4_HEADER_WITHOUT_IPS = 12
IPV4_HEADER_WITH_SOURCE_IP = 16
IPV4_HEADER_WITH_DESTINATION_IP = 20
IPV4_TO_PROTOCOL = 9
ARP_TO_SOURCE_IP = 14
ARP_TO_TARGET_IP = 24
IPV6_SOURCE_IP = 8
IPV6_DESTINATION_IP = 24


vysielajuceAdresy = []


class VysielajuceAdresy:
    def __init__(self, vysielajucaAdresa):
        self.vysielajucaAdresa = vysielajucaAdresa
        self.pocetRamcov = 0
        self.pocetRamcov += 1
    def increasePocetRamcov(self):
        self.pocetRamcov += 1


class EthernetHeader:
    def initSourceMAC(self, sourceMAC):
        self.sourceMAC = sourceMAC
    def initDestinationMAC(self, destinationMAC):
        self.destinationMAC = destinationMAC


class IPv4Header:
    def initSourceIP(self, sourceIP):
        self.sourceIP = sourceIP
    def initDestinationIP(self, destinationIP):
        self.destinationIP = destinationIP
    def initDlzkaHlavicky(self, dlzkaHlavicky):
        self.dlzkaHlavicka = dlzkaHlavicky
    def initProtocol(self, protocol):
        self.protocol = protocol


class ARPHeader:
    def initSourceIP(self, sourceIP):
        self.sourceIP = sourceIP
    def initTargetIP(self, targetIP):
        self.targetIP = targetIP


def vytvorVypisHexaGulas(bajty):
    vypisHexaGulas = ""

    for i in range(len(bajty)):
        if (i % 16 == 0) and (i != 0):
            vypisHexaGulas += "\n"
        elif (i % 8 == 0) and (i != 0):
            vypisHexaGulas += "  "
        elif i != 0:
            vypisHexaGulas += " "
        if bajty[i] < 16:
            vypisHexaGulas += "0" + str(format(bajty[i], "X"))
        else:
            vypisHexaGulas += str(format(bajty[i], "X"))

    return vypisHexaGulas


def vytvorDSTMAC(bajty):
    destinationMAC = ""

    for i in range(len(bajty)):
        if i != len(bajty):
            destinationMAC += " "
        if bajty[i] < 16:
            destinationMAC += "0" + str(format(bajty[i], "X"))
        else:
            destinationMAC += str(format(bajty[i], "X"))

    return destinationMAC


def vytvorSRCMAC(bajty):
    sourceMAC = ""

    for i in range(len(bajty)):
        if i != len(bajty):
            sourceMAC += " "
        if bajty[i] < 16:
            sourceMAC += "0" + str(format(bajty[i], "X"))
        else:
            sourceMAC += str(format(bajty[i], "X"))

    return sourceMAC


def getSourceIP(bajty):
    sourceIp = ""
    for i in range(len(bajty)):
        sourceIp += str(bajty[i])
        if (i != 3):
            sourceIp += "."
    return sourceIp


def getDestinationIP(bajty):
    destinationIp = ""
    for i in range(len(bajty)):
        destinationIp += str(bajty[i])
        if (i != 3):
            destinationIp += "."
    return destinationIp


def getSourcePort(bajty, ipv4header):
    sourcePort = ""
    for i in range(len(bajty[(ETHERNET_HEADER + ipv4header.dlzkaHlavicka):(ETHERNET_HEADER + ipv4header.dlzkaHlavicka + 2)])):
        if bajty[ETHERNET_HEADER + ipv4header.dlzkaHlavicka + i] < 16:
            sourcePort += "0" + str(format(bajty[ETHERNET_HEADER + ipv4header.dlzkaHlavicka + i], "X"))
        else:
            sourcePort += str(format(bajty[ETHERNET_HEADER + ipv4header.dlzkaHlavicka + i], "X"))
    return int(sourcePort, 16)


def getDestinationPort(bajty, ipv4header):
    destinationPort = ""
    for i in range(len(bajty[(ETHERNET_HEADER + ipv4header.dlzkaHlavicka + 2):(ETHERNET_HEADER + ipv4header.dlzkaHlavicka + 4)])):
        if bajty[ETHERNET_HEADER + ipv4header.dlzkaHlavicka + 2 + i] < 16:
            destinationPort += "0" + str(format(bajty[ETHERNET_HEADER + ipv4header.dlzkaHlavicka + 2 + i], "X"))
        else:
            destinationPort += str(format(bajty[ETHERNET_HEADER + ipv4header.dlzkaHlavicka + 2 + i], "X"))
    return int(destinationPort, 16)


def zistiSRCaDSTPortTCP(bajty, ipv4header):
    port = ""
    sourcePort = getSourcePort(bajty, ipv4header)
    destinationPort = getDestinationPort(bajty, ipv4header)
    with open("tcp_port.txt", "r") as file:
        count = 0
        for line in file:
            count += 1
            if count % 2 != 0:
                if int(line) == sourcePort:
                    port = file.readline().rstrip("\n")
                    break
    file.close()
    if (port != ""):
        print("zdrojovy port: " + str(sourcePort) + " " + port)
    else:
        print("zdrojovy port: " + str(sourcePort))
    port = ""

    with open("tcp_port.txt", "r") as file:
        count = 0
        for line in file:
            count += 1
            if count % 2 != 0:
                if int(line) == destinationPort:
                    port = file.readline().rstrip("\n")
                    break
    file.close()
    if (port != ""):
        print("cielovy port: " + str(destinationPort) + " " + port)
    else:
        print("cielovy port: " + str(destinationPort))


def zistiSRCaDSTPortUDP(bajty, ipv4header):
    sourcePort = getSourcePort(bajty, ipv4header)
    destinationPort = getDestinationPort(bajty, ipv4header)
    with open("udp_port.txt", "r") as file:
        count = 0
        for line in file:
            count += 1
            if count % 2 != 0:
                if int(line) == sourcePort:
                    print(file.readline().rstrip("\n"))
                    break
    file.close()
    print("zdrojovy port: " + str(sourcePort))

    with open("udp_port", "r") as file:
        count = 0
        for line in file:
            count += 1
            if count % 2 != 0:
                if int(line) == destinationPort:
                    print(file.readline().rstrip("\n"))
                    break
    file.close()
    print("cielovy port: " + str(destinationPort))


def zistiIPv4Protocol(ipv4header, bajty):
    with open("ipv4.txt", "r") as file:
        count = 0
        for line in file:
            count += 1
            if count % 2 != 0:
                if int(line) == ipv4header.protocol:
                    print(file.readline().rstrip("\n"))
                    break
    file.close()

    priradena = "nie"
    if (ipv4header.protocol == 6):
        for i in range(len(vysielajuceAdresy)):
            if ipv4header.sourceIP == vysielajuceAdresy[i].vysielajucaAdresa:
                vysielajuceAdresy[i].increasePocetRamcov()
                priradena = "ano"
                break
        if (priradena == "nie"):
            vysielajuceAdresy.append((VysielajuceAdresy(ipv4header.sourceIP)))
        zistiSRCaDSTPortTCP(bajty, ipv4header)
    elif (ipv4header.protocol == 17):
        zistiSRCaDSTPortUDP(bajty, ipv4header)


def analyzujIPv4(bajty):
    ipv4header = IPv4Header()
    ipv4header.initDestinationIP(getDestinationIP(bajty[(ETHERNET_HEADER + IPV4_HEADER_WITH_SOURCE_IP):(ETHERNET_HEADER + IPV4_HEADER_WITH_DESTINATION_IP)]))
    ipv4header.initSourceIP(getSourceIP(bajty[(ETHERNET_HEADER + IPV4_HEADER_WITHOUT_IPS):(ETHERNET_HEADER + IPV4_HEADER_WITH_SOURCE_IP)]))
    ipv4header.initDlzkaHlavicky((int(bajty[14]) & 15) * 4)
    ipv4header.initProtocol(int(bajty[(ETHERNET_HEADER + IPV4_TO_PROTOCOL)]))

    print("zdrojova IP adresa: " + ipv4header.sourceIP)
    print("cielova IP adresa: " + ipv4header.destinationIP)
    zistiIPv4Protocol(ipv4header, bajty)


def analyzujARP(bajty):
    arpHeader = ARPHeader()
    arpHeader.initSourceIP(getSourceIP(bajty[(ETHERNET_HEADER + ARP_TO_SOURCE_IP):(ETHERNET_HEADER + ARP_TO_SOURCE_IP + 4)]))
    arpHeader.initTargetIP(getDestinationIP(bajty[(ETHERNET_HEADER + ARP_TO_TARGET_IP):(ETHERNET_HEADER + ARP_TO_TARGET_IP + 4)]))

    print("zdrojova IP adresa: " + arpHeader.sourceIP)
    print("cielova IP adresa: " + arpHeader.targetIP)


def vypisMACAdries(bajty):
    ethernetHeader = EthernetHeader()
    ethernetHeader.initDestinationMAC(vytvorDSTMAC(bajty[0:ETHERNET_START_SOURCE_MAC]))
    ethernetHeader.initSourceMAC(vytvorSRCMAC(bajty[ETHERNET_START_SOURCE_MAC:ETHERNET_WITHOUT_LENGTH]))
    print("Zdrojova MAC adresa: " + ethernetHeader.sourceMAC)
    print("Cielova MAC adresa: " + ethernetHeader.destinationMAC)


def getSNAPEthernetType(bajty):
    ethernetType = ""

    for i in range(len(bajty[20:22])):
        if bajty[20 + i] < 16:
            ethernetType += "0" + str(format(bajty[20 + i], "X"))
        else:
            ethernetType += str(format(bajty[20 + i], "X"))
    ethernetTypeHodnota = int(ethernetType, 16)

    with open("ethernet_type.txt", "r") as file:
        count = 0
        for line in file:
            count += 1
            if count % 2 != 0:
                if int(line) == ethernetTypeHodnota:
                    print(file.readline().rstrip("\n"))
                    break
    file.close()


def getIEEE(bajty):
    with open("ieee_saps.txt", "r") as file:
        count = 0
        for line in file:
            count += 1
            if count % 2 != 0:
                if int(line) == int(bajty[15]):
                    print("IEEE 802.3 " + file.readline().rstrip("\n"))
                    if int(bajty[15]) == 170:
                        getSNAPEthernetType(bajty)
                        break
                    else:
                        break
    file.close()


def printEthernetType(ethernetTypeHodnota):
    print("Ethernet II")
    with open("ethernet_type.txt", "r") as file:
        count = 0
        for line in file:
            count += 1
            if count % 2 != 0:
                if int(line) == ethernetTypeHodnota:
                    print(file.readline().rstrip("\n"))
                    break
    file.close()


def checkLengthOrEthernetType(bajty):
    ethernetType = ""

    for i in range(len(bajty[ETHERNET_WITHOUT_LENGTH:ETHERNET_HEADER])):
        if bajty[ETHERNET_WITHOUT_LENGTH + i] < 16:
            ethernetType += "0" + str(format(bajty[ETHERNET_WITHOUT_LENGTH + i], "X"))
        else:
            ethernetType += str(format(bajty[ETHERNET_WITHOUT_LENGTH + i], "X"))
    ethernetTypeHodnota = int(ethernetType, 16)

    if (ethernetTypeHodnota > 1500):
        vypisMACAdries(bajty)
        printEthernetType(ethernetTypeHodnota)
        if (ethernetTypeHodnota == 2048): # IPv4
            analyzujIPv4(bajty)
        elif (ethernetTypeHodnota == 2054): # ARP
            analyzujARP(bajty)
    else:
        getIEEE(bajty)
        vypisMACAdries(bajty)


def main():
    frameNumber = 1
    pkts_list = rdpcap("C:\\Users\\Jakub.DESKTOP-0IDDC3B\\PycharmProjects\\PKS2\\eth-1.pcap")

    for i in range(len(pkts_list)):
        bajty = raw(pkts_list[i])
        vypisHexaGulas = vytvorVypisHexaGulas(bajty)
        print("ramec " + str(frameNumber))
        print("dlzka ramca poskytnuta pcap API - " + str(len(pkts_list[i])) +" B")
        if len(pkts_list[i]) <= 60:
            print("dlzka ramca prenasaneho po mediu - 64 B")
        else:
            print("dlzka ramca prenasaneho po mediu - " + str(len(pkts_list[i]) + 4) + " B")
        checkLengthOrEthernetType(bajty)
        print("")
        print(vypisHexaGulas + "\n")

        frameNumber += 1

    mostPacketSent = ""
    packetNumberMostPacketSent = 0
    print("IP adresy vysielajucich uzlov:")
    for i in range(len(vysielajuceAdresy)):
        if packetNumberMostPacketSent < vysielajuceAdresy[i].pocetRamcov:
            if mostPacketSent != vysielajuceAdresy[i].vysielajucaAdresa:
                mostPacketSent = vysielajuceAdresy[i].vysielajucaAdresa
                packetNumberMostPacketSent = vysielajuceAdresy[i].pocetRamcov
        print(vysielajuceAdresy[i].vysielajucaAdresa)

    print("\nAdresa uzla s najvacsim poctom odoslanych paketov:")
    print(mostPacketSent + "  " + str(packetNumberMostPacketSent) + " paketov")


main()