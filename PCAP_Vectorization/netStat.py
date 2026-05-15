import numpy as np
import os
import subprocess
import pyximport
pyximport.install()
import AfterImage as af

def set_afterimage_backend(use_extrapolation=False):
    global af
    if use_extrapolation:
        import AfterImage_extrapolate as selected_backend
        if not hasattr(selected_backend.incStatDB, "update_get_jitter_1D2D_Stats"):
            print("AfterImage_extrapolate is missing jitter features. Falling back to AfterImage.py.")
            import AfterImage as selected_backend
    else:
        import AfterImage as selected_backend
    af = selected_backend

class netStat:
    # Data structure for efficient network-stat queries.
    # HostLimit: no more than this many host identifiers will be tracked.
    # HostSimplexLimit: no more than this many outgoing channels from each host will be tracked.
    # Lambdas: a list of 'window sizes' (decay factors) to track for each stream. nan resolved to default [5,3,1,.1,.01]
    def __init__(self, Lambdas = np.nan, HostLimit=255,HostSimplexLimit=1000):
        if np.isnan(Lambdas):
            self.Lambdas = [5,3,1,.1,.01]
        else:
            self.Lambdas = Lambdas

        self.HostLimit = HostLimit
        self.SessionLimit = HostSimplexLimit*self.HostLimit*self.HostLimit
        self.MAC_HostLimit = self.HostLimit*10

        self.HT_jit = af.incStatDB(limit=self.HostLimit*self.HostLimit)#H-H Jitter Stats
        self.HT_MI = af.incStatDB(limit=self.MAC_HostLimit)#MAC-IP relationships
        self.HT_H = af.incStatDB(limit=self.HostLimit) #Source Host BW Stats
        self.HT_Hp = af.incStatDB(limit=self.SessionLimit)#Source Host BW Stats


    def findDirection(self,IPtype,srcIP,dstIP,eth_src,eth_dst):
        if IPtype==0:
            lstP = srcIP.rfind('.')
            src_subnet = srcIP[0:lstP:]
            lstP = dstIP.rfind('.')
            dst_subnet = dstIP[0:lstP:]
        elif IPtype==1:
            src_subnet = srcIP[0:round(len(srcIP)/2):]
            dst_subnet = dstIP[0:round(len(dstIP)/2):]
        else:
            src_subnet = eth_src
            dst_subnet = eth_dst

        return src_subnet, dst_subnet

    def updateGetStats(self, IPtype, srcMAC,dstMAC, srcIP, srcProtocol, dstIP, dstProtocol, datagramSize, timestamp):

        Hstat = np.zeros((3*len(self.Lambdas,))) # 15
        for i in range(len(self.Lambdas)):
            Hstat[(i*3):((i+1)*3)] = self.HT_H.update_get_1D_Stats(srcIP, timestamp, datagramSize, self.Lambdas[i])

        MIstat =  np.zeros((3*len(self.Lambdas,)))
        for i in range(len(self.Lambdas)):
            MIstat[(i*3):((i+1)*3)] = self.HT_MI.update_get_1D_Stats(srcMAC+srcIP, timestamp, datagramSize, self.Lambdas[i])

        # Main difference between the proposed 135-dimensional feature extraction method and the original 115-dimensional Kitsune method
        # Host-Host Channel statistics capture 1D and 2D characteristics of packet size and count dynamics
        HHstat =  np.zeros((7*len(self.Lambdas,)))
        for i in range(len(self.Lambdas)):
            HHstat[(i*7):((i+1)*7)] = self.HT_H.update_get_1D2D_Stats(srcIP, dstIP,timestamp,datagramSize,self.Lambdas[i])

        HHstat_jit = np.zeros((7 * len(self.Lambdas, )))
        for i in range(len(self.Lambdas)):
            HHstat_jit[(i * 7):((i + 1) * 7)] = self.HT_H.update_get_jitter_1D2D_Stats(srcIP, dstIP,timestamp,0,self.Lambdas[i],isTypeDiff=True)

        HpHpstat =  np.zeros((7*len(self.Lambdas,)))
        if srcProtocol == 'arp':
            for i in range(len(self.Lambdas)):
                HpHpstat[(i*7):((i+1)*7)] = self.HT_Hp.update_get_1D2D_Stats(srcMAC, dstMAC, timestamp, datagramSize, self.Lambdas[i])
        else:
            for i in range(len(self.Lambdas)):
                HpHpstat[(i*7):((i+1)*7)] = self.HT_Hp.update_get_1D2D_Stats(srcIP + srcProtocol, dstIP + dstProtocol, timestamp, datagramSize, self.Lambdas[i])
        window1 = np.concatenate((Hstat[0:3],MIstat[0:3],HHstat[0:7],HHstat_jit[0:7],HpHpstat[0:7]))
        window2 = np.concatenate((Hstat[3:6], MIstat[3:6], HHstat[7:14], HHstat_jit[7:14], HpHpstat[7:14]))
        window3 = np.concatenate((Hstat[6:9], MIstat[6:9], HHstat[14:21], HHstat_jit[14:21], HpHpstat[14:21]))
        window4 = np.concatenate((Hstat[9:12], MIstat[9:12], HHstat[21:28], HHstat_jit[21:28], HpHpstat[21:28]))
        window5 = np.concatenate((Hstat[12:15], MIstat[12:15], HHstat[28:35], HHstat_jit[28:35], HpHpstat[28:35]))
        return np.concatenate((window1,window2,window3,window4,window5))

    def getNetStatHeaders(self):
        MIstat_headers = []
        Hstat_headers = []
        HHstat_headers = []
        HHjitstat_headers = []
        HpHpstat_headers = []

        for i in range(len(self.Lambdas)):
            MIstat_headers += ["MI_dir_"+h for h in self.HT_MI.getHeaders_1D(Lambda=self.Lambdas[i],ID=None)]
            Hstat_headers +=["H_"+h for h in self.HT_H.getHeaders_1D(Lambda=self.Lambdas[i],ID=None)]
            HHstat_headers += ["HH_"+h for h in self.HT_H.getHeaders_1D2D(Lambda=self.Lambdas[i],IDs=None,ver=2)]
            HHjitstat_headers += ["HH_jit_"+h for h in self.HT_jit.getHeaders_1D(Lambda=self.Lambdas[i],ID=None)]
            HpHpstat_headers += ["HpHp_" + h for h in self.HT_Hp.getHeaders_1D2D(Lambda=self.Lambdas[i], IDs=None, ver=2)]
        return MIstat_headers + Hstat_headers + HHstat_headers + HHjitstat_headers + HpHpstat_headers
