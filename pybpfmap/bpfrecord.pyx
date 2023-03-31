'''Python presentation of BPF map records'''

# pybpfmap, Copyright (c) 2023 RedHat Inc
# pybpfmap, Copyright (c) 2023 Cambridge Greys Ltd

# This source code is licensed under both the BSD-style license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.


import struct
import sys
import os
import cython

from libc.stdlib cimport malloc, free
from libc.string cimport memset

def buff_copy(dest, src, length):
    '''Copy buffer, works for anything - bytes(), bytearray(), str() and does not get confused
       by zeroes as str(n)cpy
    '''
    if src.__class__ == str:
        asc = src.encode("ascii")
        for index in range(0, length):
            if index >= len(asc):
                dest[index] = 0
            else:
                dest[index] = asc[index]
    else:
        for index in range(0, length):
            if index >= len(src):
                dest[index] = 0
            else:
                dest[index] = src[index]

class IterableBuff():
    '''Class representing an iterable over a known length *char'''

    def __init__(self, buff, buflen):
        self.buff = buff
        self.buflen = buflen
        self.loc = 0

    def __iter__(self):
        '''Return an iterator over self'''
        self.loc = 0
        return self

    def __next__(self):
        '''Iterable support'''
        if self.loc >= self.buflen:
            self.loc = 0
            raise StopIteration
        if self.buff is None:
            raise ValueError

        ret = self.buff[self.loc]
        self.loc = self.loc + 1
        return ret

    def __getitem__(self, item):
        '''Get an individual item'''
        if self.buff is None:
            raise ValueError
        if item < 0 or item >= self.length:
            raise IndexError
        return self.buff[item]


class BPFRecord(IterableBuff):
    '''Class representing a single bpf map record,
    args:
        json template - list of tuples (field name, format) where
        format is a python struct format specifier. For example
        Q is 64 bit long. For more information consult struct documentation
        order is parsing order "=" - machine endian, "<" - little endian
        ">" - big endian, "!" - network byte order.
    '''
    def __init__(self, json_template, buff=None, order="="):

        self.template = order
        self.parsed = {}
        self.json_template = json_template
        for key, template in json_template:
            self.template = self.template + template

        self.compiled = struct.Struct(self.template)

        super().__init__(buff, struct.calcsize(self.template))

    def unpack(self, buff=None):
        '''Parse the buffer. Buffer is bytes or something that
        behaves like bytes, f.e. cython char*
        returns a dict object built according to the template
        '''

        if buff is None:
            if self.buffer is not None:
                data = self.compiled.unpack(self.buff)
            else:
                raise ValueError
        else:
            data = self.compiled.unpack(buff)
        pos = 0
        parsed = {}
        for item in data:
            key, value = self.json_template[pos]
            parsed[key] = item
            pos = pos + 1
        return parsed

    def pack(self, arg):
        '''Build a buffer from a dict according to the
        template. The buffer is a bytes() object.
        '''

        if arg is None:
            raise ValueError

        to_pack = []

        for specs in self.json_template:
            to_pack.append(arg[specs[0]])

        return self.compiled.pack(*to_pack)

class BPFMap():
    '''Class representing a BPF Map. 
    init takes as arguments fd, maptype, name, keysize, value, max_entries.
    If create is False, map will use the fd passed at init time. If it is
    True, the map will be created
    '''
    def __init__(self, fd, map_type, name, key_size, value_size, max_entries, create=False, btf_params=None):

        cdef bpf_map_create_opts opts

        self.fd = fd
        self.keysize = key_size
        self.valuesize = value_size
        self.map_type = map_type
        self.btf_params = btf_params

        if create:
            memset(&opts, 0, sizeof(bpf_map_create_opts))
            opts.sz = sizeof(bpf_map_create_opts)
            if btf_params is not None:
                opts.btf_fd = btf_params["btf_fd"]
                opts.btf_key_type_id = btf_params["btf_key_type_id"]
                opts.btf_value_type_id = btf_params["btf_value_type_id"]
                opts.btf_vmlinux_value_type_id = btf_params["btf_vmlinux_value_type_id"]

            self.fd = bpf_map_create(map_type, name, key_size, value_size, max_entries, &opts)

        if self.fd < 0:
            raise ValueError

    def pin_map(self, pathname):
        '''Pin BPF map to pathname specified in the argument'''
        return not bpf_obj_pin(self.fd, pathname)


    def update_elem(self, key, value):
        '''Update an element supplied as a Python object.
        key and value should be bytes() objects or cython
        char* pointers.
        '''

        # cython performs an autoconversion from bytes() to char*

        cdef char *ckey = key
        cdef char *cvalue = value
        
        return not bpf_map_update_elem(self.fd, <void *>ckey, <void *>cvalue, 0)

    def lookup_elem(self, key):
        '''Lookup an element for key. Key must be a bytes() object
        or a cython char* pointer. Returns a bytes() object if found.
        '''

        # cython performs an autoconversion from bytes() to char*

        cdef char *ckey = key
        cdef char *cvalue = <char*>malloc(self.valuesize)

        ret = bpf_map_lookup_elem(self.fd, <void*>ckey, <void*>cvalue)

        if ret == 0:
            # note - we build a new bytes() out of the result
            # this way we can free our buffer which is malloc'ed
            # and not from the python memory pool. 
            # This rather ugly and perl-like incantation prevents
            # cython from treating the result as a char
            result = bytes(<bytes>cvalue[:self.valuesize])
        else:
            result = None

        free(cvalue)

        return result

    def lookup_and_delete(self, key):
        '''Lookup and delete an element by key. Key is a bytes() object.
        Returns a bytes() object if found, otherwise returns None
        '''

        # cython performs an autoconversion from bytes() to char*

        cdef char *ckey = key
        cdef char *cvalue = <char*>malloc(self.valuesize)

        if cvalue is None:
            raise MemoryError

        if not bpf_map_lookup_and_delete_elem(self.fd, <void *>ckey, <void *>cvalue):
            # note - we build a new bytes() out of the result
            # this way we can free our buffer which is malloc'ed
            # and not from the python memory pool. 
            # This rather ugly and perl-like incantation prevents
            # cython from treating the result as a char
            result = bytes(<bytes>cvalue[:self.valuesize])
        else:
            result = None

        free(cvalue)

        return result

    def delete(self, key):
        '''Delete an element based on key supplied as a bytes() object'''

        cdef char *ckey = key
        return not bpf_map_delete_elem(self.fd, ckey)

    def get_next_key(self, key):
        '''Get next key from key based on key supplied as a bytes() object'''

        cdef char *ckey = key
        cdef char *cnextkey = <char*>malloc(self.keysize)

        if cnextkey is None:
            raise MemoryError


        if not bpf_map_get_next_key(self.fd, <void *>ckey, <void *>cnextkey):
            # note - we build a new bytes() out of the result
            # this way we can free our buffer which is malloc'ed
            # and not from the python memory pool. 
            # This rather ugly and perl-like incantation prevents
            # cython from treating the result as a char
            result = bytes(<bytes>cnextkey[:self.keysize])
        else:
            result = None

        free(cnextkey)

        return result

    def __del__(self):
        '''Cleanup and delete the map'''
        if self.fd > 0:
            os.close(self.fd)

class PinnedBPFMap():
    '''Class representing a Pinned BPF Map. Takes one argument - pinned
    pathname. Key and value sizes are obtained from the kernel
    using the object info call.
    '''
    def __init__(self, pathname):
        cdef bpf_map_info *info = <bpf_map_info *>malloc(sizeof(bpf_map_info))
        cdef unsigned int size = sizeof(bpf_map_info)

        try:
            self.pathname = pathname

            fd = bpf_obj_get(pathname)

            if fd < 0:
                raise ValueError

            if bpf_obj_get_info_by_fd(fd, info, &size):
                raise ValueError
            else:
                btf_params = None
                if info.btf_value_type_id != 0 or info.btf_key_type_id !=0:
                    btf_params = {
                        "id" : info.id,
                        "btf_key_type_id"  : info.btf_key_type_id,
                        "btf_value_type_id" : info.btf_value_type_id,
                        "btf_vmlinux_value_type_id" : info.btf_vmlinux_value_type_id
                    }
                super().__init__(fd, info.type, info.name, info.key_size, info.value_size, info.max_entries, create=False, btf_params=btf_params)

        finally:
            free(info)
