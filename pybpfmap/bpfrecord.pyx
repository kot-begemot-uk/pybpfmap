'''Python presentation of BPF map records'''

import struct
import sys
import cython

from libc.stdlib cimport malloc, free

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
        '''Parse the buffer'''

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
        '''Parse the buffer'''

        if arg is None:
            raise ValueError

        to_pack = []

        for specs in self.json_format:
            to_pack.append(arg[specs[0]])

        return self.compiled.pack(*to_pack)

class BPFMap():
    '''Class representing a BPF Map'''
    def __init__(self, pathname):
        cdef bpf_map_info *info = <bpf_map_info *>malloc(sizeof(bpf_map_info))
        cdef unsigned int size = sizeof(bpf_map_info)

        try:
            self.pathname = pathname

            self.fd = bpf_obj_get(pathname)

            if self.fd < 0:
                raise ValueError


            if bpf_obj_get_info_by_fd(self.fd, info, &size):
                raise ValueError
            else:
                self.keysize = info.key_size
                self.valuesize = info.value_size

        finally:
            free(info)



    def update_elem(self, key, value):
        '''Update an element supplied as a Python object'''
        cdef char *ckey = key
        cdef char *cvalue = value

        return not bpf_map_update_elem(self.fd, ckey, cvalue, 0)

    def lookup_elem(self, key):
        '''Lookup an element for key'''

        cdef char *ckey = key
        cdef char *cvalue = <char*>malloc(self.valuesize)

        ret = bpf_map_lookup_elem(self.fd, ckey, cvalue)

        if ret == 0:
            result = bytes(cvalue)
        else:
            result = None

        free(cvalue)

        return result
        
    def lookup_and_delete(self, key, value):
        '''Lookup and delete an element supplied as a Python object'''

        cdef char *ckey = key 
        cdef char *cvalue = <char*>malloc(self.valuesize)

        if cvalue is None:
            raise MemoryError

        if not bpf_map_lookup_and_delete_elem(self.fd, ckey, cvalue):
            result = bytes(cvalue)
        else:
            result = None

        free(cvalue)

        return result
       
    def delete(self, key):
        '''Delete an element supplied as a Python object'''

        cdef char *ckey = key
        return not bpf_map_delete_elem(self.fd, ckey)

    def get_next_key(self, key, nextkey):
        '''Get Next Key'''

        cdef char *ckey = key
        cdef char *cnextkey = <char*>malloc(self.keysize)

        if cnextkey is None:
            raise MemoryError


        if not bpf_map_get_next_key(self.fd, ckey, cnextkey):
            result = bytes(cnextkey)
        else:
            result = None

        free(cnextkey)

        return result
