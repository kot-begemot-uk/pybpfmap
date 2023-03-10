# pybpfmap, Copyright (c) 2023 RedHat Inc
# pybpfmap, Copyright (c) 2023 Cambridge Greys Ltd

# This source code is licensed under both the BSD-style license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.

cdef extern from "stdint.h":
    pass

cdef extern from "linux/types.h":
    pass

cdef extern from "linux/bpf.h":

    struct bpf_map_info:
        unsigned int type
        unsigned int key_size
        unsigned int value_size
        unsigned int max_entries
        char name[16]

cdef extern from "bpf/libbpf_common.h":
    pass

cdef extern from "bpf/libbpf_legacy.h":
    pass

cdef extern from "bpf/bpf.h":

    struct bpf_map_create_opts:
        size_t sz

    enum bpf_map_type:
        pass


    bint bpf_map_update_elem(int fd, const void *key, const void *value, unsigned long int flags)
    bint bpf_map_lookup_elem(int fd, const void *key, void *value)
    bint bpf_map_lookup_elem_flags(int fd, const void *key, void *value, unsigned long int flags)
    bint bpf_map_lookup_and_delete_elem(int fd, const void *key, void *value)
    bint bpf_map_delete_elem(int fd, const void *key)
    bint bpf_map_get_next_key(int fd, const void *key, void *next_key)
    bint bpf_map_freeze(int fd)
    
    int bpf_obj_get(const char *pathname)

    bint bpf_obj_get_info_by_fd(int bpf_fd, void *info, unsigned int *info_len)

    int bpf_map_create(bpf_map_type map_type, const char *map_name, \
                        unsigned int key_size, unsigned int value_size, \
                        unsigned int max_entries, const bpf_map_create_opts *opts)

    bint bpf_obj_pin(int fd, const char *pathname);
