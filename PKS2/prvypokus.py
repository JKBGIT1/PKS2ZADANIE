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
    def initTyp(self, typ):
        self.typ = typ


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


class IPv6Header:
    def initSourceIP(self, sourceIP):
        self.sourceIP = sourceIP
    def initDestinationIP(self, destinationIP):
        self.destinationIP = destinationIP


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


def getEthernetType(bajty):
    ethernetType = ""

    for i in range(len(bajty[12:14])):
        if bajty[i] < 16:
            ethernetType += "0" + str(format(bajty[i], "X"))
        else:
            ethernetType += str(format(bajty[i], "X"))
    ethernetTypeHodnota = int(ethernetType, 16)

    if (ethernetTypeHodnota > 1500):
        return 1
    else:
        if (bajty[15] == 255): # bajty[15] je hned dalsie pole za dlzkou a 255 = FF, teda to je RAW
            return 4
        elif (bajty[15] == 170): # bajty[15] je hned dalsie pole za dlzkou a 170 = AA, tead to je LLC + SNAP
            return 3
        else: # dorobit pre SNAP bez LLC
            return 5


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


def valueEthernetType(bajty):
    ethernetType = ""

    for i in range(len(bajty)):
        if bajty[i] < 16:
            ethernetType += "0" + str(format(bajty[i], "X"))
        else:
            ethernetType += str(format(bajty[i], "X"))
    ethernetTypeHodnota = int(ethernetType, 16)

    return ethernetTypeHodnota


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


def analyzujIPv4(bajty):
    print("IPv4")
    ipv4header = IPv4Header()
    ipv4header.initDestinationIP(getDestinationIP(bajty[(ETHERNET_HEADER + IPV4_HEADER_WITH_SOURCE_IP):(ETHERNET_HEADER + IPV4_HEADER_WITH_DESTINATION_IP)]))
    ipv4header.initSourceIP(getSourceIP(bajty[(ETHERNET_HEADER + IPV4_HEADER_WITHOUT_IPS):(ETHERNET_HEADER + IPV4_HEADER_WITH_SOURCE_IP)]))
    ipv4header.initDlzkaHlavicky((int(bajty[14]) & 15) * 4)
    ipv4header.initProtocol(int(bajty[(ETHERNET_HEADER + IPV4_TO_PROTOCOL)]))

    print("zdrojova IP adresa: " + ipv4header.sourceIP)
    print("cielova IP adresa: " + ipv4header.destinationIP)
    if ipv4header.protocol == 1:  # 0x01 -> ICMP
        print("ICMP")
    elif ipv4header.protocol == 6:  # 0x06 -> TCP
        print("TCP")
        for i in range(len(vysielajuceAdresy)):
            if ipv4header.sourceIP == vysielajuceAdresy[i].vysielajucaAdresa:
                vysielajuceAdresy[i].increasePocetRamcov()
                return
        vysielajuceAdresy.append(VysielajuceAdresy(ipv4header.sourceIP))
    elif ipv4header.protocol == 17:  # 0x11 -> UDP
        print("UDP")
    else:
        print("Iny protocol ako TCP, ICMP alebo UDP")


def analyzujARP(bajty):
    print("ARP")
    arpHeader = ARPHeader()
    arpHeader.initSourceIP(getSourceIP(bajty[(ETHERNET_HEADER + ARP_TO_SOURCE_IP):(ETHERNET_HEADER + ARP_TO_SOURCE_IP + 4)]))
    arpHeader.initTargetIP(getDestinationIP(bajty[(ETHERNET_HEADER + ARP_TO_TARGET_IP):(ETHERNET_HEADER + ARP_TO_TARGET_IP + 4)]))

    print("zdrojova IP adresa: " + arpHeader.sourceIP)
    print("cielova IP adresa: " + arpHeader.targetIP)


def getIPv6SourceIP(bajty):
    sourceIp = ""
    smallCounts = ""
    for i in range(len(bajty)):
        smallCounts += str(format(bajty[i], "X"))
        if i % 2 == 0 and i != 0:
            sourceIp += smallCounts
            smallCounts = ""
            if i < len(bajty) - 2:
                sourceIp += ":"
    return sourceIp


def getIPv6DestinationIP(bajty):
    destinationIp = ""
    smallCounts = ""
    for i in range(len(bajty)):
        smallCounts += str(format(bajty[i], "X"))
        if i % 2 == 0 and i != 0:
            destinationIp += smallCounts
            smallCounts = ""
            if i < len(bajty) - 2:
                destinationIp += ":"
    return destinationIp


def analyzujIPv6(bajty):
    print("IPv6")
    ipv6Header = IPv6Header()
    ipv6Header.initSourceIP(getIPv6SourceIP(bajty[(ETHERNET_HEADER + IPV6_SOURCE_IP):(ETHERNET_HEADER + IPV6_DESTINATION_IP)]))
    ipv6Header.initDestinationIP(getIPv6DestinationIP(bajty[(ETHERNET_HEADER + IPV6_DESTINATION_IP):(ETHERNET_HEADER + IPV6_DESTINATION_IP + 16)]))

    print("zdrojova IP adresa: " + ipv6Header.sourceIP)
    print("cielova IP adresa: " + ipv6Header.destinationIP)


def vypisMACAdriesAIP(bajty):
    ethernetHeader = EthernetHeader()
    ethernetHeader.initDestinationMAC(vytvorDSTMAC(bajty[0:ETHERNET_START_SOURCE_MAC]))
    ethernetHeader.initSourceMAC(vytvorSRCMAC(bajty[ETHERNET_START_SOURCE_MAC:ETHERNET_WITHOUT_LENGTH]))
    ethernetHeader.initTyp(valueEthernetType(bajty[ETHERNET_WITHOUT_LENGTH:ETHERNET_HEADER]))
    print("Zdrojova MAC adresa: " + ethernetHeader.sourceMAC)
    print("Cielova MAC adresa: " + ethernetHeader.destinationMAC)

    if ethernetHeader.typ == 2048: # teda 0x0800 -> IPv4
        analyzujIPv4(bajty)
    elif ethernetHeader.typ == 2054: # 0x0806 -> ARP
        analyzujARP(bajty)
    elif ethernetHeader.typ == 34525: # 0x86DD -> IPv6
        analyzujIPv6(bajty)


def vypisMACAdries(bajty):
    ethernetHeader = EthernetHeader()
    ethernetHeader.initDestinationMAC(vytvorDSTMAC(bajty[0:ETHERNET_START_SOURCE_MAC]))
    ethernetHeader.initSourceMAC(vytvorSRCMAC(bajty[ETHERNET_START_SOURCE_MAC:ETHERNET_WITHOUT_LENGTH]))
    ethernetHeader.initTyp(valueEthernetType(bajty[ETHERNET_WITHOUT_LENGTH:ETHERNET_HEADER]))
    print("Zdrojova MAC adresa: " + ethernetHeader.sourceMAC)
    print("Cielova MAC adresa: " + ethernetHeader.destinationMAC)


def main():
    frameNumber = 1
    pkts_list = rdpcap("C:\\Users\\Jakub.DESKTOP-0IDDC3B\\PycharmProjects\\PKS2\\sr-header.pcap")

    for i in range(len(pkts_list)):
        bajty = raw(pkts_list[i])
        vypisHexaGulas = vytvorVypisHexaGulas(bajty)
        print("ramec " + str(frameNumber))
        print("dlzka ramca poskytnuta pcap API - " + str(len(pkts_list[i])) +" B")
        print("dlzka ramca prenasaneho po mediu - " + " B")
        flagForEthernet = getEthernetType(bajty[12:])
        if flagForEthernet == 1:
            print("Ethernet II")
            vypisMACAdriesAIP(bajty)
        else:
            if flagForEthernet == 2:
                print("IEEE 802.3 LLC")
            elif flagForEthernet == 3:
                print("IEEE 802.3 LLC + SNAP")
            elif flagForEthernet == 4:
                print("IEEE 802.3 - Raw")
            else:
                print("IEEE 802.3")
            vypisMACAdries(bajty)
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