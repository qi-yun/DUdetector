from Cython.Build import cythonize
from setuptools import Extension, setup
import numpy as np

setup(
    name="AfterImage_extrapolate",
    ext_modules=cythonize(
        [
            Extension(
                "AfterImage_extrapolate",
                ["AfterImage_extrapolate.pyx"],
                include_dirs=[np.get_include()],
            )
        ]
    ),
)
