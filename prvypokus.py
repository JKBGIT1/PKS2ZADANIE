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
ARP_TO_OPERATION = 6
UDP_HEADER = 8


icmpList = []
tftpList = []
komunikaciaTftp = []
vysielajuceAdresy = []
requestARP = []
replyARP = []
httpList = []
httpsList = []
telnetList = []
sshList = []
ftpDataList = []
ftpControlList = []

UDPPort = -1
TFTPKomunikacia = 0

ICMPkomunikacia = 0
ICMPSourceIP = ""
ICMPDestinatioIP = ""


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
    def initZakladneParametre(self, cisloRamca, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas):
        self.cisloRamca = cisloRamca
        self.dlzkaPoMediu = dlzkaPoMediu
        self.dlzkaPcap = dlzkaPcap
        self.vypisHexaGulas = vypisHexaGulas
    def initSourceMAC(self, sourceMAC):
        self.sourceMAC = sourceMAC
    def initDestination(self, destinationMAC):
        self.destinationMAC = destinationMAC
    def initOperation(self, operation):
        self.operation = operation


class ICMProtocol:
    def initZakladneParametre(self, cisloRamca, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas):
        self.cisloRamca = cisloRamca
        self.dlzkaPoMediu = dlzkaPoMediu
        self.dlzkaPcap = dlzkaPcap
        self.vypisHexaGulas = vypisHexaGulas
    def initSourceMac(self, sourceMAC):
        self.sourceMAC = sourceMAC
    def initDestinationMAC(self, destinationMAC):
        self.destinationMAC = destinationMAC
    def initIPv4Header(self, ipv4header):
        self.ipv4header = ipv4header
    def initType(self, typeHodnota, typeNazov):
        self.typeHodnota = typeHodnota
        self.typeNazov = typeNazov


class TFTProtocol:
    def initZakladneParametre(self, cisloRamca, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, komunikacia):
        self.cisloRamca = cisloRamca
        self.dlzkaPoMediu = dlzkaPoMediu
        self.dlzkaPcap = dlzkaPcap
        self.vypisHexaGulas = vypisHexaGulas
        self.komunikacia = komunikacia
    def initSourceMac(self, sourceMAC):
        self.sourceMAC = sourceMAC
    def initDestinationMAC(self, destinationMAC):
        self.destinationMAC = destinationMAC
    def initIPv4Header(self, ipv4header):
        self.ipv4header = ipv4header
    def initUDPPorty(self, sourcePort, destinationPort):
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort


class IPv4Ramce:
    def initZakladneParametre(self, cisloRamca, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas):
        self.cisloRamca = cisloRamca
        self.dlzkaPoMediu = dlzkaPoMediu
        self.dlzkaPcap = dlzkaPcap
        self.vypisHexaGulas = vypisHexaGulas
    def initSoureceMac(self, sourceMAC):
        self.sourceMAC = sourceMAC
    def initDestinationMAC(self, destinationMAC):
        self.destinationMAC = destinationMAC
    def initIPV4Header(self, ipv4header):
        self.ipv4header = ipv4header
    def initPorty(self, sourcePort, sourceNazov, destinatonPort, destinationNazov):
        self.sourcePort = sourcePort
        self.sourceNazov = sourceNazov
        self.destinationPort = destinatonPort
        self.destinationNazov = destinationNazov


def vypisICMP(icmpProtocol):
    global ICMPSourceIP, ICMPDestinatioIP, ICMPkomunikacia
    if (ICMPSourceIP == "" and ICMPDestinatioIP == ""):
        ICMPkomunikacia += 1
        print("KOMUNIKACIA: " + str(ICMPkomunikacia))
        ICMPSourceIP = icmpProtocol.ipv4header.sourceIP
        ICMPDestinatioIP = icmpProtocol.ipv4header.destinationIP
    elif ((ICMPSourceIP != icmpProtocol.ipv4header.sourceIP or ICMPDestinatioIP != icmpProtocol.ipv4header.destinationIP) and
          (ICMPSourceIP != icmpProtocol.ipv4header.destinationIP or ICMPDestinatioIP != icmpProtocol.ipv4header.sourceIP)):
        ICMPkomunikacia += 1
        print("KOMUNIKACIA: " + str(ICMPkomunikacia))
        ICMPSourceIP = icmpProtocol.ipv4header.sourceIP
        ICMPDestinatioIP = icmpProtocol.ipv4header.destinationIP
    print("ramec " + str(icmpProtocol.cisloRamca))
    print("dlzka ramca poskytnuta pcap API - " + str(icmpProtocol.dlzkaPcap))
    print("dlzka ramca prenasaneho po mediu - " + str(icmpProtocol.dlzkaPoMediu))
    print("Ethernet II")
    print("Zdrojova MAC adresa: " + str(icmpProtocol.sourceMAC))
    print("Cielova MAC adresa: " + str(icmpProtocol.destinationMAC))
    print("IPv4")
    print("zdrojova IP adresa: " + str(icmpProtocol.ipv4header.sourceIP))
    print("cielova IP adresa: " + str(icmpProtocol.ipv4header.destinationIP))
    print("ICMP")
    print("Type: " + str(icmpProtocol.typeHodnota) + " " + str(icmpProtocol.typeNazov))
    print(icmpProtocol.vypisHexaGulas + "\n")


def vypisTFTP(tftpProtocol):
    global TFTPKomunikacia
    if (tftpProtocol.komunikacia != TFTPKomunikacia):
        TFTPKomunikacia += 1
        print("KOMUNIKACIA: " + str(tftpProtocol.komunikacia))
    print("ramec " + str(tftpProtocol.cisloRamca))
    print("dlzka ramca poskytnuta pcap API - " + str(tftpProtocol.dlzkaPcap))
    print("dlzka ramca prenasaneho po mediu - " + str(tftpProtocol.dlzkaPoMediu))
    print("Ethernet II")
    print("Zdrojova MAC adresa: " + str(tftpProtocol.sourceMAC))
    print("Cielova MAC adresa: " + str(tftpProtocol.destinationMAC))
    print("IPv4")
    print("zdrojova IP adresa: " + str(tftpProtocol.ipv4header.sourceIP))
    print("cielova IP adresa: " + str(tftpProtocol.ipv4header.destinationIP))
    print("UDP")
    print("zdrojovy port: " + str(tftpProtocol.sourcePort))
    print("cielovy port: " + str(tftpProtocol.destinationPort))
    print(tftpProtocol.vypisHexaGulas + "\n")


def vypisARP(arpFrame):
    print("Zdrojova IP: " + arpFrame.sourceIP + ", Cielova IP: " + arpFrame.targetIP)
    print("ramec " + str(arpFrame.cisloRamca))
    print("dlzka ramca poskytnuta pcap API - " + str(arpFrame.dlzkaPcap) + " B")
    print("dlzka ramca prenasaneho po mediu - " + str(arpFrame.dlzkaPoMediu) + " B")
    print("Ethernet II")
    print("ARP")
    print("Zdrojova MAC adresa: " + arpFrame.sourceMAC)
    print("Cielova MAC adresa: " + arpFrame.destinationMAC)
    print(arpFrame.vypisHexaGulas + "\n")


def vypisIPv4Ramec(ramec):
    print("ramec " + str(ramec.cisloRamca))
    print("dlzka ramca poskytnuta pcap API - " + str(ramec.dlzkaPcap))
    print("dlzka ramca prenasaneho po mediu - " + str(ramec.dlzkaPoMediu))
    print("Ethernet II")
    print("Zdrojova MAC adresa: " + str(ramec.sourceMAC))
    print("Cielova MAC adresa: " + str(ramec.destinationMAC))
    print("IPv4")
    print("zdrojova IP adresa: " + str(ramec.ipv4header.sourceIP))
    print("cielova IP adresa: " + str(ramec.ipv4header.destinationIP))
    print("TCP")
    print("zdrojovy port: " + str(ramec.sourcePort) + " " + str(ramec.sourceNazov))
    print("cielovy port: " + str(ramec.destinationPort) + " " + str(ramec.destinationNazov))
    print(ramec.vypisHexaGulas + "\n")


def vytvorVypisHexaGulas(bajty): # vytvorim si gulas, ktory musim vypisat po analyze daneho ramca
    vypisHexaGulas = ""

    for i in range(len(bajty)):
        if (i % 16 == 0) and (i != 0): # ked mam 16 bajtov v jednom riadku, tak ich oddelim novym riadkom
            vypisHexaGulas += "\n"
        elif (i % 8 == 0) and (i != 0): # v strede riadku dám medzeru pre priehladnost
            vypisHexaGulas += "  "
        elif i != 0: # oddelujem bity medzerami
            vypisHexaGulas += " "
        if bajty[i] < 16: # ak je ak je bajt mensi ako 16, tak by mi mohlo vypisat len 0 az F, len ja potrebujem 2 miesta, preto davam pred hodnotu 0
            vypisHexaGulas += "0" + str(format(bajty[i], "X"))
        else: # v opacnom priprade len priradim prekonvertovane cislo do hexadeximalnej sustavy do vypisu
            vypisHexaGulas += str(format(bajty[i], "X"))

    return vypisHexaGulas # vratim navarene


def vytvorDSTMAC(bajty): # funkcia mi vrati destination MAC address v hexadecimalnom tvare
    destinationMAC = ""

    for i in range(len(bajty)):
        if i != len(bajty): # oddelujem jednotlive bity medzerami
            destinationMAC += " "
        if bajty[i] < 16: # zase ten isty problem ako pri vypisHexaGulas
            destinationMAC += "0" + str(format(bajty[i], "X"))
        else:
            destinationMAC += str(format(bajty[i], "X"))

    return destinationMAC


def vytvorSRCMAC(bajty): # vytvaram analogicky ako pri destination MAC address, len je ine rozmedzie bajtov passovane do funkcie
    sourceMAC = ""

    for i in range(len(bajty)):
        if i != len(bajty):
            sourceMAC += " "
        if bajty[i] < 16:
            sourceMAC += "0" + str(format(bajty[i], "X"))
        else:
            sourceMAC += str(format(bajty[i], "X"))

    return sourceMAC


def getSourceIP(bajty): # dostanem source IP z funkcie
    sourceIp = ""
    for i in range(len(bajty)):
        sourceIp += str(bajty[i])
        if (i != 3): # oddelujem kazdy oktet bodkou
            sourceIp += "."
    return sourceIp


def getDestinationIP(bajty): # funkcia funguje presne ako getSourceIP, len do nej passujem ine rozmedzie bajtov
    destinationIp = ""
    for i in range(len(bajty)):
        destinationIp += str(bajty[i])
        if (i != 3):
            destinationIp += "."
    return destinationIp


def getSourcePort(bajty, ipv4header): # dostanem source port z TCP alebo UDP
    sourcePort = ""
    for i in range(len(bajty[(ETHERNET_HEADER + ipv4header.dlzkaHlavicka):(ETHERNET_HEADER + ipv4header.dlzkaHlavicka + 2)])):
        if bajty[ETHERNET_HEADER + ipv4header.dlzkaHlavicka + i] < 16:
            sourcePort += "0" + str(format(bajty[ETHERNET_HEADER + ipv4header.dlzkaHlavicka + i], "X"))
        else:
            sourcePort += str(format(bajty[ETHERNET_HEADER + ipv4header.dlzkaHlavicka + i], "X"))
    return int(sourcePort, 16)


def getDestinationPort(bajty, ipv4header): # dostanem destination port z TCP alebo UDP
    destinationPort = ""
    for i in range(len(bajty[(ETHERNET_HEADER + ipv4header.dlzkaHlavicka + 2):(ETHERNET_HEADER + ipv4header.dlzkaHlavicka + 4)])):
        if bajty[ETHERNET_HEADER + ipv4header.dlzkaHlavicka + 2 + i] < 16:
            destinationPort += "0" + str(format(bajty[ETHERNET_HEADER + ipv4header.dlzkaHlavicka + 2 + i], "X"))
        else:
            destinationPort += str(format(bajty[ETHERNET_HEADER + ipv4header.dlzkaHlavicka + 2 + i], "X"))
    return int(destinationPort, 16)


def vytvorIPv4Ramec(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, sourceNazov, destinationPort, destinationNazov):
    ramec = IPv4Ramce()
    ramec.initZakladneParametre(frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas)
    ramec.initDestinationMAC(vytvorDSTMAC(bajty[0:ETHERNET_START_SOURCE_MAC]))
    ramec.initSoureceMac(vytvorSRCMAC(bajty[ETHERNET_START_SOURCE_MAC:ETHERNET_WITHOUT_LENGTH]))
    ramec.initIPV4Header(ipv4header)
    ramec.initPorty(sourcePort, sourceNazov, destinationPort, destinationNazov)
    return ramec


def pridajHTTPDoListu(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, sourceNazov, destinationPort, destinationNazov):
    ramec = vytvorIPv4Ramec(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, sourceNazov, destinationPort, destinationNazov)
    httpList.append(ramec)


def pridajHTTPSDoListu(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, sourceNazov, destinationPort, destinationNazov):
    ramec = vytvorIPv4Ramec(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, sourceNazov, destinationPort, destinationNazov)
    httpsList.append(ramec)


def pridajTelnetDoListu(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, sourceNazov, destinationPort, destinationNazov):
    ramec = vytvorIPv4Ramec(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, sourceNazov, destinationPort, destinationNazov)
    telnetList.append(ramec)


def pridajSSHDoListu(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, sourceNazov, destinationPort, destinationNazov):
    ramec = vytvorIPv4Ramec(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, sourceNazov, destinationPort, destinationNazov)
    sshList.append(ramec)


def pridajFtpDataDoListu(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, sourceNazov, destinationPort, destinationNazov):
    ramec = vytvorIPv4Ramec(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, sourceNazov, destinationPort, destinationNazov)
    ftpDataList.append(ramec)


def pridajFtpControlDoListu(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, sourceNazov, destinationPort, destinationNazov):
    ramec = vytvorIPv4Ramec(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, sourceNazov, destinationPort, destinationNazov)
    ftpControlList.append(ramec)


def zistiSRCaDSTPortTCP(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas):
    port = ""
    sourcePort = getSourcePort(bajty, ipv4header)
    destinationPort = getDestinationPort(bajty, ipv4header)
    # hodnoty, ktore mi boli vratene z funkcii budem vyhldavat v textaku pre tcp porty
    with open("tcp_port.txt", "r") as file:
        count = 0
        for line in file:
            count += 1
            if count % 2 != 0:
                if int(line) == sourcePort:
                    port = file.readline().rstrip("\n")
                    break
    file.close()
    if (port != ""): # ak je to znamy port, tak ho vypisem aj s jeho cislom
        print("zdrojovy port: " + str(sourcePort) + " " + port)
    else: # inak vypisem iba cislo
        print("zdrojovy port: " + str(sourcePort))
    sourcePortNazov = port
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

    if (sourcePortNazov == "http" or port == "http"):
        pridajHTTPDoListu(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, sourcePortNazov, destinationPort, port)
    if (sourcePortNazov == "https (ssl)" or port == "https (ssl)"):
        pridajHTTPSDoListu(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, sourcePortNazov, destinationPort, port)
    if (sourcePortNazov == "telnet" or port == "telnet"):
        pridajTelnetDoListu(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, sourcePortNazov, destinationPort, port)
    if (sourcePortNazov == "ssh" or port == "ssh"):
        pridajSSHDoListu(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, sourcePortNazov, destinationPort, port)
    if (sourcePortNazov == "ftp-data" or port == "ftp-data"):
        pridajFtpDataDoListu(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, sourcePortNazov, destinationPort, port)
    if (sourcePortNazov == "ftp-control" or port == "ftp-control"):
        pridajFtpControlDoListu(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, sourcePortNazov, destinationPort, port)


def pridajTFTPDoListu(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, destinationPort, cisloKomunikacia):
    tftpProtocol = TFTProtocol()
    tftpProtocol.initZakladneParametre(frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, cisloKomunikacia)
    tftpProtocol.initDestinationMAC(vytvorDSTMAC(bajty[0:ETHERNET_START_SOURCE_MAC]))
    tftpProtocol.initSourceMac(vytvorSRCMAC(bajty[ETHERNET_START_SOURCE_MAC:ETHERNET_WITHOUT_LENGTH]))
    tftpProtocol.initIPv4Header(ipv4header)
    tftpProtocol.initUDPPorty(sourcePort, destinationPort)
    komunikaciaTftp.append(tftpProtocol)


def pridajTFTPKomunikaciuDoListu(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, destinationPort):
    global komunikaciaTftp
    if (TFTPKomunikacia == 0):
        pridajTFTPDoListu(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, destinationPort, TFTPKomunikacia + 1)
    else:
        tftpList.append(komunikaciaTftp)
        komunikaciaTftp = []
        pridajTFTPDoListu(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, destinationPort, TFTPKomunikacia + 1)


def zistiSRCaDSTPortUDP(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas):
    portSRC = ""
    portDST = ""
    global UDPPort, TFTPKomunikacia
    sourcePort = getSourcePort(bajty, ipv4header)
    destinationPort = getDestinationPort(bajty, ipv4header)

    with open("udp_port.txt", "r") as file:
        count = 0
        for line in file:
            count += 1
            if count % 2 != 0:
               if int(line) == sourcePort:
                    portSRC = file.readline().rstrip("\n")
                    break
    file.close()
    if (portSRC != ""):
        print("zdrojovy port: " + str(sourcePort) + " " + portSRC)
    else:
        print("zdrojovy port: " + str(sourcePort))

    with open("udp_port.txt", "r") as file:
        count = 0
        for line in file:
            count += 1
            if count % 2 != 0:
                if int(line) == destinationPort:
                    portDST = file.readline().rstrip("\n")
                    break
    file.close()
    if (portDST != ""):
        print("cielovy port: " + str(destinationPort) + " " + portDST)
    else:
        print("cielovy port: " + str(destinationPort))

    if (portSRC == "tftp" or portDST == "tftp"):
        if (portSRC == "tfpt"):
            UDPPort = destinationPort
        else:
            UDPPort = sourcePort
        pridajTFTPKomunikaciuDoListu(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, destinationPort)
        TFTPKomunikacia += 1
    elif (UDPPort == sourcePort or UDPPort == destinationPort):
        pridajTFTPDoListu(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas, sourcePort, destinationPort, TFTPKomunikacia)

def getICMPType(icmpTypeHodnota):
    icmpTypeNazov = ""
    with open("icmp_type.txt", "r") as file:
        count = 0
        for line in file:
            count += 1
            if count % 2 != 0:
                if int(line) == icmpTypeHodnota:
                    icmpTypeNazov = file.readline().rstrip("\n")
                    break
    file.close()
    return icmpTypeNazov


def pridajICMPDoListu(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas):
    icmpProtocol = ICMProtocol()
    icmpProtocol.initZakladneParametre(frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas)
    icmpProtocol.initDestinationMAC(vytvorDSTMAC(bajty[0:ETHERNET_START_SOURCE_MAC]))
    icmpProtocol.initSourceMac(vytvorSRCMAC(bajty[ETHERNET_START_SOURCE_MAC:ETHERNET_WITHOUT_LENGTH]))
    icmpProtocol.initIPv4Header(ipv4header)
    icmpTypeHodnota = int(bajty[ETHERNET_HEADER + ipv4header.dlzkaHlavicka])
    icmpTypeNazov = getICMPType(icmpTypeHodnota)
    icmpProtocol.initType(icmpTypeHodnota, icmpTypeNazov)
    icmpList.append(icmpProtocol)


def zistiIPv4Protocol(ipv4header, bajty, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas):
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
    if (ipv4header.protocol == 6): # TCP
        for i in range(len(vysielajuceAdresy)):
            if ipv4header.sourceIP == vysielajuceAdresy[i].vysielajucaAdresa:
                vysielajuceAdresy[i].increasePocetRamcov()
                priradena = "ano"
                break
        if (priradena == "nie"): # ak sa vysielajuca IP v zozname este nenachadza, tak ju tam pridam, inak iba zvysim pocet ramcov, ktore odoslala
            vysielajuceAdresy.append((VysielajuceAdresy(ipv4header.sourceIP)))
        zistiSRCaDSTPortTCP(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas)
    elif (ipv4header.protocol == 17): # UDP
        zistiSRCaDSTPortUDP(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas)
    elif (ipv4header.protocol == 1): # ICMP
        pridajICMPDoListu(bajty, ipv4header, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas)


def analyzujIPv4(bajty, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas):
    ipv4header = IPv4Header()
    ipv4header.initDestinationIP(getDestinationIP(bajty[(ETHERNET_HEADER + IPV4_HEADER_WITH_SOURCE_IP):(ETHERNET_HEADER + IPV4_HEADER_WITH_DESTINATION_IP)]))
    ipv4header.initSourceIP(getSourceIP(bajty[(ETHERNET_HEADER + IPV4_HEADER_WITHOUT_IPS):(ETHERNET_HEADER + IPV4_HEADER_WITH_SOURCE_IP)]))
    ipv4header.initDlzkaHlavicky((int(bajty[14]) & 15) * 4)
    ipv4header.initProtocol(int(bajty[(ETHERNET_HEADER + IPV4_TO_PROTOCOL)]))

    print("zdrojova IP adresa: " + ipv4header.sourceIP)
    print("cielova IP adresa: " + ipv4header.destinationIP)
    zistiIPv4Protocol(ipv4header, bajty, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas)


def analyzujARP(bajty, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas):
    arpHeader = ARPHeader()
    arpHeader.initZakladneParametre(frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas)
    arpHeader.initDestination(vytvorDSTMAC(bajty[0:ETHERNET_START_SOURCE_MAC]))
    arpHeader.initSourceMAC(vytvorSRCMAC(bajty[ETHERNET_START_SOURCE_MAC:ETHERNET_WITHOUT_LENGTH]))
    arpHeader.initSourceIP(getSourceIP(bajty[(ETHERNET_HEADER + ARP_TO_SOURCE_IP):(ETHERNET_HEADER + ARP_TO_SOURCE_IP + 4)]))
    arpHeader.initTargetIP(getDestinationIP(bajty[(ETHERNET_HEADER + ARP_TO_TARGET_IP):(ETHERNET_HEADER + ARP_TO_TARGET_IP + 4)]))
    operation = int.from_bytes(bajty[ETHERNET_HEADER + ARP_TO_OPERATION:ETHERNET_HEADER + ARP_TO_OPERATION + 2], byteorder='big')
    if (operation == 1):
        arpHeader.initOperation("ARP - Request")
        requestARP.append(arpHeader)
    elif (operation == 2):
        arpHeader.initOperation("ARP - Reply")
        replyARP.append(arpHeader)

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
    nasiel = "nie"

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
                    nasiel = "ano"
                    ethernetType = file.readline().rstrip("\n")
                    break
    if (nasiel == "ano"):
        print(ethernetType)
    else:
        print("Hodnota ether typu: " + str(ethernetTypeHodnota))
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


def checkLengthOrEthernetType(bajty, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas):
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
            analyzujIPv4(bajty, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas)
        elif (ethernetTypeHodnota == 2054): # ARP
            analyzujARP(bajty, frameNumber, dlzkaPoMediu, dlzkaPcap, vypisHexaGulas)
    else:
        getIEEE(bajty)
        vypisMACAdries(bajty)


def main():
    frameNumber = 1
    dlzkaPoMediu = 0
    pkts_list = rdpcap("C:\\Users\\Jakub.DESKTOP-0IDDC3B\\PycharmProjects\\PKS2\\vzorky_pcap_na_analyzu\\eth-6.pcap")
    for i in range(len(pkts_list)):
        bajty = raw(pkts_list[i])
        vypisHexaGulas = vytvorVypisHexaGulas(bajty)
        print("ramec " + str(frameNumber))
        print("dlzka ramca poskytnuta pcap API - " + str(len(pkts_list[i])) +" B")
        if len(pkts_list[i]) <= 60:
            print("dlzka ramca prenasaneho po mediu - 64 B")
            dlzkaPoMediu = 64
        else:
            print("dlzka ramca prenasaneho po mediu - " + str(len(pkts_list[i]) + 4) + " B")
            dlzkaPoMediu = str(len(pkts_list[i]) + 4)
        checkLengthOrEthernetType(bajty, frameNumber, dlzkaPoMediu, len(pkts_list[i]), vypisHexaGulas)
        print("")
        print(vypisHexaGulas + "\n")

        frameNumber += 1

    if (len(komunikaciaTftp) > 0):
        tftpList.append(komunikaciaTftp)

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

    operacia = ""
    while(operacia != "k"):
        operacia = input("Vypisat ICMP - i, TFTP - t, ARP - a, HTTP - h, HTTPS - hs, Telnet - te, FTP-data - fd, FTP-control -fc, koniec - k\n")
        if (operacia == "i"):
            global ICMPkomunikacia
            ICMPkomunikacia = 0
            print("\n------------------")
            print("|ICMP komunikacia|")
            print("------------------")
            for i in range(len(icmpList)):
                vypisICMP(icmpList[i])
        elif (operacia == "t"):
            global TFTPKomunikacia
            TFTPKomunikacia = 0
            print("\n------------------")
            print("|TFTP komunikacia|")
            print("------------------")
            for i in range(len(tftpList)):
                if (len(tftpList[i]) > 20):
                    for j in range(0,10):
                        vypisTFTP(tftpList[i][j])
                    for j in range(len(tftpList[i]) - 10, len(tftpList[i])):
                        vypisTFTP(tftpList[i][j])
                else:
                    for j in range(len(tftpList[i])):
                        vypisTFTP(tftpList[i][j])
        elif (operacia == 'a'):
            neuplne = []
            komunikaciaCislo = 1
            print("\n-----------------")
            print("|ARP komunikacia|")
            print("-----------------")
            for i in range(len(requestARP)):
                for j in range(len(replyARP)):
                    if (requestARP[i].targetIP == replyARP[j].sourceIP):
                        print("UPLNA")
                        print("KOMUNIKACIA c." + str(komunikaciaCislo))
                        print("ARP-Request, IP adresa: " + requestARP[i].targetIP + ", MAC adresa: ???")
                        vypisARP(requestARP[i])
                        print("ARP-Reply, IP adresa: " + replyARP[j].sourceIP + ", MAC adresa: " + replyARP[j].sourceMAC)
                        vypisARP(replyARP[j])
                        komunikaciaCislo += 1
                    elif (j == len(replyARP) - 1):
                        neuplne.append(requestARP[i])
            komunikaciaCislo = 1
            for i in range(len(neuplne)):
                print("NEUPLNA")
                print("KOMUNIKACIA c." + str(komunikaciaCislo))
                print("ARP-Request, IP adresa: " + neuplne[i].targetIP + ", MAC adresa: ???")
                vypisARP(neuplne[i])
                komunikaciaCislo += 1
        elif (operacia == 'h'):
            print("\n------------------")
            print("|HTTP komunikacia|")
            print("------------------")
            for i in range(len(httpList)):
                vypisIPv4Ramec(httpList[i])
        elif(operacia == 'hs'):
            print("\n-------------------")
            print("|HTTPS komunikacia|")
            print("-------------------")
            for i in range(len(httpsList)):
                vypisIPv4Ramec(httpsList[i])
        elif(operacia == 'te'):
            print("\n--------------------")
            print("|TELNET komunikacia|")
            print("--------------------")
            for i in range(len(telnetList)):
                vypisIPv4Ramec(telnetList[i])
        elif(operacia == 'fd'):
            print("\n----------------------")
            print("|FTP-data komunikacia|")
            print("----------------------")
            for i in range(len(ftpDataList)):
                vypisIPv4Ramec(ftpDataList[i])
        elif(operacia == 'fc'):
            print("\n-------------------------")
            print("|FTP-control komunikacia|")
            print("-------------------------")
            for i in range(len(ftpControlList)):
                vypisIPv4Ramec(ftpControlList[i])


main()