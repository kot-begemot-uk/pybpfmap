'''Python presentation of BPF map records'''

# pybpfmap, Copyright (c) 2023 RedHat Inc
# pybpfmap, Copyright (c) 2023 Cambridge Greys Ltd

# This source code is licensed under both the BSD-style license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.


from struct import Struct, calcsize
import sys
import os
import cython
import btfparse

from libc.stdlib cimport malloc, free
from libc.string cimport memset

KEY = 0
VALUE = 1

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

def produce_template(type_info):
    '''Generate a Struct template out of type info'''
    if type(type_info) is tuple:
        return produce_template(type_info[1])
    elif type(type_info) is list:
        res = ""
        for item in type_info:
            res = res + produce_template(item)
        return res
    else:
        if type(type_info) is not str:
            raise TypeError
        return type_info

def walk_template(type_info, data, pos):
    '''Walk a template assigning data as we go along'''
    if type(type_info) is tuple:
        return {type_info[0]:walk_template(type_info[1], data, pos)}
    elif type(type_info) is list:
        if type(type_info[0]) is tuple:
            res = {}
        else:
            res = []
        for item in type_info:
            if type(item) is tuple:
                res[item[0]] = walk_template(item[1], data, pos)
            else:
                res.append(walk_template(item, data, pos))
            pos += 1
        return res
    else:
        return data[pos]



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
        self.template += produce_template(self.json_template)

        self.compiled = Struct(self.template)

        super().__init__(buff, calcsize(self.template))

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
        return walk_template(self.json_template, data, 0)

    def pack(self, arg):
        '''Build a buffer from a dict according to the
        template. The buffer is a bytes() object.
        '''

        if arg is None:
            raise ValueError

        to_pack = []

        for specs in self.json_template:
            if type(arg[specs[0]]) is list:
                to_pack.extend(arg[specs[0]])
            else:
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
        self.parsers = [None, None]

        if create:
            # We do not support btf_params here. The restrictions on .fd in the opts make
            # this support useable only for someone loading a map out of an elf loader
            self.fd = bpf_map_create(map_type, name, key_size, value_size, max_entries, NULL)

        if self.fd < 0:
            raise ValueError

    def pin_map(self, pathname):
        '''Pin BPF map to pathname specified in the argument'''
        return not bpf_obj_pin(self.fd, pathname)

    def convert(self, value, parser):
        '''Convert value to bytes'''

        if type(value) is dict:
            if self.parsers[parser] is None:
                raise ValueError
            cvalue = self.parsers[parser].pack(value)
        elif type(value) is str:
            cvalue = value.encode("ascii")
        else:
            cvalue = value

        return cvalue

    def update_elem(self, key, value):
        '''Update an element supplied as a Python object.
        key and value should be bytes() objects or cython
        char* pointers.
        '''
        key = self.convert(key, KEY)
        value = self.convert(value, VALUE)

        cdef char *ckey = <char *>key
        cdef char *cvalue = <char *>value

        return not bpf_map_update_elem(self.fd, <void *>ckey, <void *>cvalue, 0)

    def lookup_elem(self, key, want_hash=False):
        '''Lookup an element for key. Key must be a bytes() object
        or a cython char* pointer. Returns a bytes() object if found.
        '''

        key = self.convert(key, KEY)

        cdef char *ckey = <char *>key
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

        if want_hash:
            return self.parsers[VALUE].unpack(result)

        return result

    def lookup_and_delete(self, key, want_hash=False):
        '''Lookup and delete an element by key. Key is a bytes() object.
        Returns a bytes() object if found, otherwise returns None
        '''

        # cython performs an autoconversion from bytes() to char*

        key = self.convert(key, KEY)

        cdef char *ckey = <char *>key
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

        if want_hash:
            return self.pasers[VALUE].unpack(result)

        return result


    def delete(self, key):
        '''Delete an element based on key supplied as a bytes() object'''

        key = self.convert(key, KEY)

        cdef char *ckey = <char *>key
        return not bpf_map_delete_elem(self.fd, ckey)

    def get_next_key(self, key):
        '''Get next key from key based on key supplied as a bytes() object'''

        key = self.convert(key, KEY)

        cdef char *ckey = <char *>key
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

    def generate_parsers(self, key_pinfo, value_pinfo):
        '''Generate parsing templates for map key and data'''
        try:
            self.parsers[KEY] = BPFRecord(key_pinfo)
        except TypeError:
            pass
        try:
            self.parsers[VALUE] = BPFRecord(value_pinfo)
        except TypeError:
            pass

    def generate_parsers_from_btf(self, path="/sys/kernel/btf/vmlinux"):
        '''Generate parsing templates for map key and data from btf'''
        B = btfparse.BTFBlob(open(path, "br").read())
        B.parse()
        key_pinfo = B.elements[self.btf_params["btf_key_type_id"]].generate_pinfo()
        value_pinfo = B.elements[self.btf_params["btf_value_type_id"]].generate_pinfo()
        self.generate_parsers(key_pinfo, value_pinfo)

    def __del__(self):
        '''Cleanup and delete the map'''
        if self.fd > 0:
            os.close(self.fd)

class PinnedBPFMap(BPFMap):
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
                    # for some reason kernel params are off by one compared to
                    # what our parser yields from /sys/kernel/btf/vmlinux
                    btf_params = {
                        "id" : info.id,
                        "btf_key_type_id"  : info.btf_key_type_id - 1,
                        "btf_value_type_id" : info.btf_value_type_id - 1,
                        "btf_vmlinux_value_type_id" : info.btf_vmlinux_value_type_id - 1
                    }
                super().__init__(fd, info.type, info.name, info.key_size, info.value_size, info.max_entries, create=False, btf_params=btf_params)

        finally:
            free(info)
