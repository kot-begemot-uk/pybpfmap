# pybpfmap Copyright (c) 2023 RedHat Inc
# pybpfmap Copyright (c) 2023 Cambridge Greys Ltd

# This source code is licensed under both the BSD-style license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select at your option one of the above-listed licenses.

cdef extern from "bpf/bpf.h":
    cpdef enum bpf_map_type:
        BPF_MAP_TYPE_UNSPEC
        BPF_MAP_TYPE_HASH
        BPF_MAP_TYPE_ARRAY
        BPF_MAP_TYPE_PROG_ARRAY
        BPF_MAP_TYPE_PERF_EVENT_ARRAY
        BPF_MAP_TYPE_PERCPU_HASH
        BPF_MAP_TYPE_PERCPU_ARRAY
        BPF_MAP_TYPE_STACK_TRACE
        BPF_MAP_TYPE_CGROUP_ARRAY
        BPF_MAP_TYPE_LRU_HASH
        BPF_MAP_TYPE_LRU_PERCPU_HASH
        BPF_MAP_TYPE_LPM_TRIE
        BPF_MAP_TYPE_ARRAY_OF_MAPS
        BPF_MAP_TYPE_HASH_OF_MAPS
        BPF_MAP_TYPE_DEVMAP
        BPF_MAP_TYPE_SOCKMAP
        BPF_MAP_TYPE_CPUMAP
        BPF_MAP_TYPE_XSKMAP
        BPF_MAP_TYPE_SOCKHASH
        BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
        BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
        BPF_MAP_TYPE_QUEUE
        BPF_MAP_TYPE_STACK
        BPF_MAP_TYPE_SK_STORAGE
        BPF_MAP_TYPE_DEVMAP_HASH
        BPF_MAP_TYPE_STRUCT_OPS
        BPF_MAP_TYPE_RINGBUF
        BPF_MAP_TYPE_INODE_STORAGE
        BPF_MAP_TYPE_TASK_STORAGE
        BPF_MAP_TYPE_BLOOM_FILTER
        BPF_MAP_TYPE_USER_RINGBUF
