# pybpfmap
Python tooling to access bpf maps.

Pybpfmap requires a recent libbpf (0.7 onwards) and cpython 3.0.

To build pybpfmap:

```
python3 setup.py build_ext -i 
```

To use pybpfmap:
```
#!/usr/bin/python3

import bpfrecord

b = bpfrecord.BPFMap(bytes("/sys/fs/bpf/test-map".encode("ascii"))

value = b.lookup_elem(key)
```

All arguments are expected to be bytes() or strings in ascii encoding, all results are bytes or boolean (whatever is applicable).

