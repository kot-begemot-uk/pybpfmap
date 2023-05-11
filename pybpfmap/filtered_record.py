'''BPF Record filtering'''

# pybpfmap, Copyright (c) 2023 RedHat Inc
# pybpfmap, Copyright (c) 2023 Cambridge Greys Ltd

# This source code is licensed under both the BSD-style license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.

from bpfrecord import PinnedBPFMap

def check_perms(mask, data, will_write=False):
    '''Generate a Struct template out of isinstance info'''

    if data is None:
        return None

    if isinstance(mask, dict):
        for key, value in mask.items():
            data[key] = check_perms(value, data[key], will_write)
    elif isinstance(mask, list):
        index = 0
        for item in mask:
            data[index] = check_perms(item, data[index], will_write)
            index += 1
    else:
        if not isinstance(mask, str):
            raise TypeError
        if mask == "R":
            if will_write:
                return None
        elif mask == "X":
            return None
    return data

def update_record(existing, new_value):
    '''Update an existing record, skipping Nones in the supplied value'''

    if new_value is None:
        return existing

    if isinstance(existing, dict):
        for key, value in existing.items():
            if isinstance(value, dict) or isinstance(value, list):
                existing[key] = update_record(value, new_value[key])
    elif isinstance(existing, list):
        for index in range(0, len(existing)):
            if isinstance(existing[index], dict) or isinstance(existing[index], list):
                existing[index] = update_record(existing[index], new_value[index])
    return new_value

class FilteredBPFMap(PinnedBPFMap):
    '''Filtering can be applied only to an existing pin.
    That is on purpose. If you want to give a client only
    a limited read-only view, giving him rights to create
    a map is a bit of an oxymoron'''

    def __init__(self, pathname, mask, can_create=True, can_delete=True, map_type=None, name=None, key_size=None, value_size=None, max_entries=None, btf_params=None):
        super().__init__(pathname, map_type=map_type, name=name, key_size=key_size, value_size=value_size, max_entries=max_entries, btf_params=btf_params)
        self.mask = mask
        self.can_create = can_create
        self.can_delete = can_delete

    def update_elem(self, key, value):
        '''Update an element supplied as a python object. Use mask
        to limit fields which can be updated.
        '''

        existing = super().lookup_elem(key, want_parsed=True)
        if existing is None:
            if self.can_create:
                return self.update_elem(key, value)
            raise ValueError

        update_record(existing, check_perms(self.mask, value))
        super().update_elem(key, existing)
        return True

    def lookup_elem(self, key):
        '''Lookup element and filter out "unwanted" fields'''

        return check_perms(self.mask, super().lookup_elem(key, want_parsed=True))


    def delete(self, key):
        '''Delete an element if permitted'''

        if self.can_delete:
            return super().delete(key)
        raise ValueError

    def lookup_and_delete(self, key):
        '''Lookup a record, delete if allowed'''

        if self.can_delete:
            elem = super().lookup_and_delete(key)
            return check_perms(self.mask, elem)

        raise ValueError
