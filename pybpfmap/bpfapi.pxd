cdef extern from "stdint.h":
    pass

cdef extern from "linux/types.h":
    pass

cdef extern from "linux/bpf.h":
    struct bpf_map_info:
        unsigned int key_size
        unsigned int value_size

cdef extern from "bpf/libbpf_common.h":
    pass

cdef extern from "bpf/libbpf_legacy.h":
    pass

cdef extern from "bpf/bpf.h":

    bint bpf_map_update_elem(int fd, const void *key, const void *value, unsigned long int flags)
    bint bpf_map_lookup_elem(int fd, const void *key, void *value)
    bint bpf_map_lookup_elem_flags(int fd, const void *key, void *value, unsigned long int flags)
    bint bpf_map_lookup_and_delete_elem(int fd, const void *key, void *value)
    bint bpf_map_delete_elem(int fd, const void *key)
    bint bpf_map_get_next_key(int fd, const void *key, void *next_key)
    bint bpf_map_freeze(int fd)
    
    int bpf_obj_get(const char *pathname)

    bint bpf_obj_get_info_by_fd(int bpf_fd, void *info, unsigned int *info_len)
