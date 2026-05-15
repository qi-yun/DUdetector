import numpy as np

class Normalizor:
    def __init__(self):
        self.max = None
        self.min = None

    def fit(self, X):
        X = np.array(X)
        self.max = np.max(X, axis=0)
        self.min = np.min(X, axis=0)

    def normalize(self, X):
        assert(self.min is not None and self.max is not None)
        return (X - self.min) / (self.max - self.min)

    def arctan_normalization(self,value):
        """Arctangent normalization maps values into [-1, 1].
        Positive inputs map to [0, 1], and negative inputs map to [-1, 0].
        """
        new_value = np.arctan(value) * (2 / np.pi)
        return new_value

    def denormalize(self, X):
        assert(self.min is not None and self.max is not None)
        return X * (self.max - self.min) + self.min

