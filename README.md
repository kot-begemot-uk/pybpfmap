# pybpfmap
Python tooling to access bpf maps.

Pybpfmap requires a recent libbpf (0.7 onwards) and cpython 3.0.

To build pybpfmap:

```
python3 setup.py build_ext -i 
```

## To use pybpfmap:
```
#!/usr/bin/python3

import bpfrecord

b = bpfrecord.BPFMap(bytes("/sys/fs/bpf/test-map".encode("ascii"))

value = b.lookup_elem(key)
```

All arguments are expected to be bytes() or strings in ascii encoding, all results are bytes or boolean (whatever is applicable).

## To use the BPFRecord parser 

Parser is initialised using a list of field:format specifiers. It is possible to specify an optional byte order

Example

```
p = bpfrecord.BPFRecord([
    ("byte_field1", "B"), 
    ("byte_field2", "B"), 
    ("2byte_padding","H),
    ("8_byte_unsigned_long","Q")
    ])
    
```
Will create a parser in native byte order which will unpack() 12 byte data as:
```
{
    "byte_field1":value1,
    "byte_field2":value2, 
    "2byte_padding":valueH,
    "8_byte_unsigned_long":valueQ
}
```
and pack() a struct with these fields into 12 byte data
