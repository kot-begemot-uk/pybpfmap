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
import pybpfmap.btfparse
from pybpfmap.map_types import BPF_MAP_TYPE_RINGBUF

from libc.stdlib cimport malloc, free
from libc.string cimport memset

KEY = 0
VALUE = 1

NO_LOOKUP = [BPF_MAP_TYPE_RINGBUF]
NO_DELETE = [BPF_MAP_TYPE_RINGBUF]
NO_GET_NEXT_KEY = [BPF_MAP_TYPE_RINGBUF]
NO_UPDATE = [BPF_MAP_TYPE_RINGBUF]

BPF_RINGBUF_BUSY_BIT        = (1 << 31)
BPF_RINGBUF_DISCARD_BIT     = (1 << 30)
BPF_RINGBUF_HDR_SZ          = 8


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
                data = self.compiled.unpack(self.buff[:self.compiled.size])
            else:
                raise ValueError
        else:
            data = self.compiled.unpack(buff[:self.compiled.size])
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

cdef roundup(argument):
    '''Abominable function to compute alignment used by the ringbuffer'''
    cdef unsigned long int arg = argument
    cdef unsigned int temp
    
    # clear out top 2 bits (discard and busy, if set)
    arg = arg & (~(BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT))
    # add length prefix
    arg += BPF_RINGBUF_HDR_SZ;
    # round up to 8 byte alignment
    if (arg % BPF_RINGBUF_HDR_SZ) > 0:
        arg += (BPF_RINGBUF_HDR_SZ - (arg % BPF_RINGBUF_HDR_SZ))

    return arg

cdef class RingBufferInfo():
    '''Cython class for the ringbuffer specific functionality.

    Limitations:
        1. Kernel to userspace just works. However, there is no 
        built inpolling mechanism. Use epoll + event framework of
        choice.
        2. Userspace to kernel is limited to ONE PRODUCER ONLY.
        The kernel can spinlock and protect the structures allowing
        multiple producers to reserve and submit. Userspace can't.
        Use by multiple userspace producer threads must be guarded by
        suitable locks. Use by multiple programs is not supported
        and will not be supported. We cannot use libbpf here, because
        it mandates a C caller, callbacks, epoll and all the rest which
        makes its use "as is" in python not very realistic.
    '''

    cdef char *data
    cdef unsigned long *consumer_pos
    cdef unsigned long *producer_pos
    cdef int record_size
    cdef unsigned long max_entries
    cdef unsigned long mask

    cdef int next_rec, next_sz

    def __cinit__(self, fd, max_entries, record_size):

        data = NULL
        consumer_pos = NULL
        producer_pos = NULL

        self.consumer_pos = <unsigned long *>mmap(<void *>NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)
        if self.consumer_pos == MAP_FAILED:
            raise ValueError

        self.producer_pos = <unsigned long *>mmap(<void *>NULL, getpagesize(), PROT_READ, MAP_SHARED, fd, getpagesize())
        if self.producer_pos == MAP_FAILED:
            raise ValueError

        self.data = <char *>mmap(<void *>NULL, max_entries * 2, PROT_READ, MAP_SHARED, fd, getpagesize() * 2)
        if self.data == MAP_FAILED:
            raise ValueError

        self.record_size = record_size
        self.max_entries = max_entries
        self.mask = max_entries - 1


    cpdef cleanup(self):
        '''Cleanup before de-allocation'''
        if self.consumer_pos != NULL and self.consumer_pos != MAP_FAILED:
            munmap(<void *>self.consumer_pos, getpagesize())
            self.consumer_pos = NULL
        if self.producer_pos != NULL and self.producer_pos != MAP_FAILED:
            munmap(<void *>self.consumer_pos, getpagesize())
            self.producer_pos = NULL
        if self.data != NULL and self.producer_pos != MAP_FAILED:
            munmap(<void *>self.consumer_pos, self.max_entries * 2)
            self.data = NULL

    def __dealloc__(self):
        self.cleanup()

    cpdef reserve(self, size):
        '''Reserve N bytes in the buffer'''
        cdef unsigned long length
        cdef unsigned long int consumer_pos = smp_load_acquire_long_int(self.consumer_pos, 0)
        cdef unsigned long int producer_pos = smp_load_acquire_long_int(self.producer_pos, 0)

        self.next_sz = size

        available = (self.mask + 1) - (producer_pos - consumer_pos)

        length = roundup(self.next_sz)

        if length > available:
            return False

        smp_store_release_int(self.data, (producer_pos & self.mask), (length | BPF_RINGBUF_BUSY_BIT))
        smp_store_release_long_int(self.producer_pos, 0, producer_pos + length)

        self.next_rec = producer_pos & self.mask

        return True

    cpdef commit(self, data, discard=False):
        '''Commmit data to buffer'''

        # Data must not be longer than the previously reserved space

        if len(data) > self.next_sz:
            return False

        length = roundup(self.next_sz + BPF_RINGBUF_HDR_SZ)

        if discard:
            length = (length | BPF_RINGBUF_DISCARD_BIT)
        else:
            # we copy the record only if we are not discarding
            for pos in range(0, len(data)):
                self.data[(self.next_rec + BPF_RINGBUF_HDR_SZ + pos) & self.mask] = data[pos]

        length = smp_store_release_int(self.data, self.next_rec, length)

        return True
                
    cpdef fetch_next_records(self):
        '''Fetch the next set of records'''

        result = list()

        cdef unsigned long int consumer_pos = smp_load_acquire_long_int(self.consumer_pos, 0)
        cdef unsigned long int producer_pos
        cdef unsigned long int length

        got_new_data = True

        while got_new_data:
            got_new_data = False
            producer_pos = smp_load_acquire_long_int(self.producer_pos, 0)
            while producer_pos > consumer_pos:
                length = smp_load_acquire_int(<unsigned long *>self.data, consumer_pos & self.mask)
                if length & BPF_RINGBUF_BUSY_BIT > 0:
                    return result

                got_new_data = True
    
                if length & BPF_RINGBUF_DISCARD_BIT == 0:
                    result.append(bytes(<bytes>self.data[(consumer_pos + BPF_RINGBUF_HDR_SZ) & self.mask:((consumer_pos + BPF_RINGBUF_HDR_SZ) & self.mask) + length]))

                consumer_pos += roundup(length)

            smp_store_release_long_int(self.consumer_pos, 0, consumer_pos);

        return result
        
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
        self.max_entries = max_entries
        self.parsers = [None, None]
        self.rb = None

        # ringbuff specific

        if create:
            # We do not support btf_params here. The restrictions on .fd in the opts make
            # this support useable only for someone loading a map out of an elf loader
            self.fd = bpf_map_create(map_type, name, key_size, value_size, max_entries, NULL)

        if self.fd < 0:
            raise ValueError

        # special case __init__s I should probably rewrite this as a MixIn
        if map_type == BPF_MAP_TYPE_RINGBUF:
            self.rb = RingBufferInfo(self.fd, self.max_entries, value_size)

    def fetch_next(self, want_parsed=False):
        if self.map_type != BPF_MAP_TYPE_RINGBUF:
            raise ValueError
        result = self.rb.fetch_next_records()

        if want_parsed and (self.parsers[VALUE] is not None):
            parsed = []
            for item in result:
                parsed.append(self.parsers[VALUE].unpack(item))
            return parsed

        return self.rb.fetch_next_records()

    def pin_map(self, pathname):
        '''Pin BPF map to pathname specified in the argument'''

        if isinstance(pathname, str):
            pathname = pathname.encode("ascii")

        return not bpf_obj_pin(self.fd, pathname)

    def convert(self, value, parser):
        '''Convert value to bytes'''

        if type(value) is bytes:
            cvalue = value
        elif type(value) is dict or type(value) is list:
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

        if self.map_type in NO_UPDATE:
            raise ValueError

        key = self.convert(key, KEY)
        value = self.convert(value, VALUE)

        cdef char *ckey = <char *>key
        cdef char *cvalue = <char *>value

        return not bpf_map_update_elem(self.fd, <void *>ckey, <void *>cvalue, 0)

    def lookup_elem(self, key, want_parsed=False):
        '''Lookup an element for key. Key must be a bytes() object
        or a cython char* pointer. Returns a bytes() object if found.
        '''

        if self.map_type in NO_LOOKUP:
            raise ValueError

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

        if want_parsed:
            return self.parsers[VALUE].unpack(result)

        return result

    def lookup_and_delete(self, key, want_parsed=False):
        '''Lookup and delete an element by key. Key is a bytes() object.
        Returns a bytes() object if found, otherwise returns None
        '''

        if self.map_type in NO_LOOKUP or self.map_type in NO_DELETE:
            raise ValueError

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

        if want_parsed:
            return self.pasers[VALUE].unpack(result)

        return result


    def delete(self, key):
        '''Delete an element based on key supplied as a bytes() object'''

        if self.map_type in NO_DELETE:
            raise ValueError

        key = self.convert(key, KEY)

        cdef char *ckey = <char *>key
        return not bpf_map_delete_elem(self.fd, ckey)

    def get_next_key(self, key):
        '''Get next key from key based on key supplied as a bytes() object'''

        if self.map_type in NO_GET_NEXT_KEY:
            raise ValueError

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

        if key_pinfo is not None:
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
        B = pybpfmap.btfparse.BTFBlob(open(path, "br").read())
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
    def __init__(self, pathname, map_type=None, name=None, key_size=None, value_size=None, max_entries=None, btf_params=None):
        cdef bpf_map_info *info = <bpf_map_info *>malloc(sizeof(bpf_map_info))
        cdef unsigned int size = sizeof(bpf_map_info)

        if isinstance(pathname, str):
            self.pathname = pathname.encode("ascii")
        else:
            self.pathname = pathname

        try:
            self.fd = -1
            fd = bpf_obj_get(self.pathname)

            if fd < 0:
                raise ValueError

            if map_type is not None:
                info.type = map_type
                info.key_size = key_size
                info.value_size = value_size
                info.max_entries = max_entries
                err = 0
            else:
                err = bpf_obj_get_info_by_fd(fd, info, &size)

            if err != 0:
                raise ValueError
            else:
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
