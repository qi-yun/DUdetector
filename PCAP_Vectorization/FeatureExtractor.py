import importlib
import importlib.util
import os
import subprocess
import sys
import netStat as ns
import csv
import numpy as np
print("Importing Scapy Library")
import os.path
import platform
import subprocess


def ensure_cython_compiled(use_extrapolation=False):
    if not use_extrapolation:
        return

    print("Importing AfterImage Cython Library")
    module_name = "AfterImage_extrapolate"
    required_method = "update_get_jitter_1D2D_Stats"
    spec = importlib.util.find_spec(module_name)
    if spec is not None:
        module = importlib.import_module(module_name)
        if hasattr(module.incStatDB, required_method):
            return
        print("AfterImage_extrapolate is missing jitter features. Rebuilding it from AfterImage_extrapolate.pyx.")

    if not os.path.isfile("AfterImage_extrapolate.pyx"):
        cmd = '"' + sys.executable + '" auto_cythonize_afterimage.py --pyx-only'
        result = subprocess.call(cmd,shell=True)
        if result != 0 or not os.path.isfile("AfterImage_extrapolate.pyx"):
            raise FileNotFoundError("AfterImage_extrapolate.pyx does not exist")

    if module_name in sys.modules:
        del sys.modules[module_name]

    cmd = '"' + sys.executable + '" setup.py build_ext --inplace'
    result = subprocess.call(cmd,shell=True)
    importlib.invalidate_caches()

    module = importlib.import_module(module_name)
    if result == 0 and hasattr(module.incStatDB, required_method):
        return

    raise ImportError("Could not build a complete AfterImage_extrapolate backend")


class FE:
    def __init__(self,file_path,limit=np.inf,use_extrapolation=False):
        ensure_cython_compiled(use_extrapolation)
        ns.set_afterimage_backend(use_extrapolation)
        self.path = file_path
        self.limit = limit
        self.parse_type = None
        self.curPacketIndx = 0
        self.tsvin = None
        self.scapyin = None

        self.__prep__()

        maxHost = 100000000000
        maxSess = 100000000000
        self.nstat = ns.netStat(np.nan, maxHost, maxSess)

    def _get_tshark_path(self):
        if platform.system() == 'Linux':
            return '/share/software/tshark-3.6/tshark'
        elif platform.system() == "Windows":
            return 'D:\\Wireshark\\tshark.exe'
        else:
            system_path = os.environ['PATH']
            for path in system_path.split(os.pathsep):
                filename = os.path.join(path, 'tshark')
                if os.path.isfile(filename):
                    return filename
        return ''

    def __prep__(self):
        if not os.path.isfile(self.path):
            print("File: " + self.path + " does not exist")
            raise Exception()

        type = self.path.split('.')[-1]

        self._tshark = self._get_tshark_path()
        if type == "tsv":
            self.parse_type = "tsv"

        elif type == "pcap" or type == 'pcapng':
            if os.path.isfile(self._tshark):
                self.pcap2tsv_with_tshark()
                self.path += ".tsv"
                self.parse_type = "tsv"
            else:
                print("tshark not found. Trying scapy...")
                self.parse_type = "scapy"
        else:
            print("File: " + self.path + " is not a tsv or pcap file")
            raise Exception()

        if self.parse_type == "tsv":
            maxInt = sys.maxsize
            decrement = True
            while decrement:
                # decrease the maxInt value by factor 10
                # as long as the OverflowError occurs.
                decrement = False
                try:
                    csv.field_size_limit(maxInt)
                except OverflowError:
                    maxInt = int(maxInt / 10)
                    decrement = True

            print("counting lines in file...")
            num_lines = sum(1 for line in open(self.path))
            print("There are " + str(num_lines - 1) + " Packets.")
            self.limit = min(self.limit, num_lines-1)
            self.tsvinf = open(self.path, 'rt', encoding="utf8")
            self.tsvin = csv.reader(self.tsvinf, delimiter='\t')
            row = self.tsvin.__next__()

        else:
            print("Reading PCAP file via Scapy...")
            self.scapyin = rdpcap(self.path)
            self.limit = len(self.scapyin)
            print("Loaded " + str(len(self.scapyin)) + " Packets.")

    def get_next_vector(self):
        if self.curPacketIndx == self.limit:
            if self.parse_type == 'tsv':
                self.tsvinf.close()
            return []

        if self.parse_type == "tsv":
            row = self.tsvin.__next__()
            IPtype = np.nan
            timestamp = row[0]
            framelen = row[1]
            srcIP = ''
            dstIP = ''
            if row[4] != '':
                srcIP = row[4]
                dstIP = row[5]
                IPtype = 0
            elif row[17] != '':
                srcIP = row[17]
                dstIP = row[18]
                IPtype = 1
            srcproto = row[6] + row[
                8]
            dstproto = row[7] + row[9]
            srcMAC = row[2]
            dstMAC = row[3]
            if srcproto == '':
                if row[12] != '':
                    srcproto = 'arp'
                    dstproto = 'arp'
                    srcIP = row[14]
                    dstIP = row[16]
                    IPtype = 0
                elif row[10] != '':
                    srcproto = 'icmp'
                    dstproto = 'icmp'
                    IPtype = 0
                elif srcIP + srcproto + dstIP + dstproto == '':
                    srcIP = row[2]
                    dstIP = row[3]

        elif self.parse_type == "scapy":
            packet = self.scapyin[self.curPacketIndx]
            IPtype = np.nan
            timestamp = packet.time
            framelen = len(packet)
            if packet.haslayer(IP):
                srcIP = packet[IP].src
                dstIP = packet[IP].dst
                IPtype = 0
            elif packet.haslayer(IPv6):
                srcIP = packet[IPv6].src
                dstIP = packet[IPv6].dst
                IPtype = 1
            else:
                srcIP = ''
                dstIP = ''

            if packet.haslayer(TCP):
                srcproto = str(packet[TCP].sport)
                dstproto = str(packet[TCP].dport)
            elif packet.haslayer(UDP):
                srcproto = str(packet[UDP].sport)
                dstproto = str(packet[UDP].dport)
            else:
                srcproto = ''
                dstproto = ''

            srcMAC = packet.src
            dstMAC = packet.dst
            if srcproto == '':
                if packet.haslayer(ARP):
                    srcproto = 'arp'
                    dstproto = 'arp'
                    srcIP = packet[ARP].psrc
                    dstIP = packet[ARP].pdst
                    IPtype = 0
                elif packet.haslayer(ICMP):
                    srcproto = 'icmp'
                    dstproto = 'icmp'
                    IPtype = 0
                elif srcIP + srcproto + dstIP + dstproto == '':
                    srcIP = packet.src
                    dstIP = packet.dst
        else:
            return []

        self.curPacketIndx = self.curPacketIndx + 1


        try:
            return self.nstat.updateGetStats(IPtype, srcMAC, dstMAC, srcIP, srcproto, dstIP, dstproto,
                                                 int(framelen),
                                                 float(timestamp))
        except Exception as e:
            print(e)
            return []


    def pcap2tsv_with_tshark(self):
        print('Parsing with tshark...')
        fields = "-e frame.time_epoch -e frame.len -e eth.src -e eth.dst -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e icmp.type -e icmp.code -e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4 -e arp.dst.hw_mac -e arp.dst.proto_ipv4 -e ipv6.src -e ipv6.dst"
        cmd =  '"' + self._tshark + '" -r '+ self.path +' -T fields '+ fields +' -E header=y -E occurrence=f > '+self.path+".tsv"
        subprocess.call(cmd,shell=True)
        print("tshark parsing complete. File saved as: "+self.path +".tsv")

    def get_num_features(self):
        return len(self.nstat.getNetStatHeaders())


    def feature_extract(self):
        fvs = []
        cnt = 0
        print("Start Feature Extracting. ")
        while(True):
            cnt += 1
            if cnt % 10000 == 0:
                print(cnt)
            x = self.get_next_vector()
            if len(x) == 0:
                break
            fvs.append(x)

        return np.array(fvs)
