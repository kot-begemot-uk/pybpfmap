# pybpfmap
Python tooling to access bpf maps.

Pybpfmap requires a recent libbpf (0.7 onwards) and cython 3.0.

To install cython using pip:
```
pip3 install "cython>=3.0.0b2"
```

To build pybpfmap:

```
python3 setup.py build_ext -i 
```
To install locally pybpfmap
```
pip install -e .
```
Note - this will just make the build directory importable without putting packages into /usr/local

## To use pybpfmap:
```
#!/usr/bin/python3

import bpfrecord

b = bpfrecord.PinnedBPFMap(bytes("/sys/fs/bpf/test-map".encode("ascii"))

KEY = bytes.fromhex("0102030405060708090a0b0c0d0e0f00")

value = b.lookup_elem(KEY)
```

For more details on how to use it see the example code in the test cases.
 

## To use the BPFRecord parser 

The parser is initialised using a list of field:format specifiers. It is possible to specify an optional byte order

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

The parser understands arrays, structs and nesting.

Arrays are represented as arrays of format specifiers: 
```
p = bpfrecord.BPFRecord([
    ("byte_field1", "B"), 
    ("array_of_8_long_ints", ["Q","Q","Q","Q","Q","Q","Q","Q"])
    ])
```

Nested structs are represented as arrays of tuples which describe type: 
```
p = bpfrecord.BPFRecord([
    ("byte_field1", "B"), 
    ("nested_struct", [("level2_1", "Q"), ("level2_2", "B")])
    ])
```
BPFMap and derived classes will accept struct/array arguments after the parsers have been initialized using generate\_parsers(). lookup(), lookup\_and\_delete() will also return
parsed results if they are given an additional want\_parsed=True argument.

## To use the MAP filtering

pybpfmap provides up to struct field/array element granular permissions to read/write to a map. This is available via the FilteredBPFMap class in the filtered\_record package.

In order to use:

1. Parsers must be initialized

1. Permission mask must be supplied at initialization

1. FilteredBPFMap supports only dict/array arguments. Passing/receiving raw buffers is not suppored.

1. The map must be created by other means (f.e. the classes in the bpfrecord package) and pinned.

This example will open an existing map and allow the consumers to read only data[2]. Attempts to write to
other fields will raise an exception, attempts to read other fields will return None.
```
p = FilteredBPFMap("/sys/fs/bpf/test_map",
                   {"data":["X","X","W","X","X","X","X","X"]},
                   map_type=BPF_MAP_TYPE_HASH, name="test_perm", key_size=16, value_size=64, max_entries=256)

p.generate_parsers([("uid", "Q"), ("gid", "Q")], [("data", ["Q","Q","Q","Q","Q","Q","Q","Q"])])
```

For more examples on how to use it see the corresponding testcases
