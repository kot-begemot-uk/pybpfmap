
from setuptools import Extension, setup
from Cython.Build import cythonize

setup(
    ext_modules = cythonize([Extension("bpfrecord", ["bpfrecord.pyx"], libraries=["bpf"])], compiler_directives={'language_level' : "3"})
)
