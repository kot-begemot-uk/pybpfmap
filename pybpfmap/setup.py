from setuptools import find_packages
from setuptools import Extension, setup
from Cython.Build import cythonize

setup(
    name='pybpfmap',
    version='0.1.0',
    license='Dual GPL2/BSD',
    author='Anton Ivanov',
    author_email='anton.ivanov@cambridgegreys.com',
    description='Tools to access BPF MAPs via Python',
    packages=find_packages(include=['pybpfmap', 'pybpfmap.*']),
    ext_modules = cythonize(
        [
            Extension("bpfrecord", ["bpfrecord.pyx"], libraries=["bpf"]),
            Extension("map_types", ["map_types.pyx"], libraries=["bpf"])
        ], compiler_directives={'language_level' : "3"})
)
