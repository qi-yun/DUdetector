from FeatureExtractor import FE
from Nomalizor import Normalizor
import numpy as np
import time

# True: use Cython backend; False: use Python backend.
USE_EXTRAPOLATION = False

fe=FE(r"./Data/mirai_1000.pcap", use_extrapolation=USE_EXTRAPOLATION)
X_unormalized = fe.feature_extract()
print(X_unormalized.shape)

n = Normalizor()
n.fit(X_unormalized)
X = n.normalize(X_unormalized)
np.savetxt("./Data/mirai_normal135.tsv",X)



