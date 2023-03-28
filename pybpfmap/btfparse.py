'''Python presentation of BTF file format'''

# pybpfmap, Copyright (c) 2023 RedHat Inc
# pybpfmap, Copyright (c) 2023 Cambridge Greys Ltd

# This source code is licensed under both the BSD-style license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.

from struct import Struct, calcsize
import sys

IS_64 = (int.bit_length(sys.maxsize) + 1 == 64)

BTFKIND_VOID           = 0
BTFKIND_INT            = 1
BTFKIND_PTR            = 2
BTFKIND_ARRAY          = 3
BTFKIND_STRUCT         = 4
BTFKIND_UNION          = 5
BTFKIND_ENUM           = 6
BTFKIND_FWD            = 7
BTFKIND_TYPEDEF        = 8
BTFKIND_VOLATILE       = 9
BTFKIND_CONST          = 10
BTFKIND_RESTRICT       = 11
BTFKIND_FUNC           = 12
BTFKIND_FUNC_PROTO     = 13
BTFKIND_VAR            = 14
BTFKIND_DATASEC        = 15
BTFKIND_FLOAT          = 16
BTFKIND_DECL_TAG       = 17
BTFKIND_TYPE_TAG       = 18
BTFKIND_ENUM64         = 19


BTFHEADER_TEMPLATE = "=HBBIIIII"
BTFHEADER = Struct(BTFHEADER_TEMPLATE)
BTFHEADER_SIZE = calcsize(BTFHEADER_TEMPLATE)

KS_IS_SIZE = [BTFKIND_INT, BTFKIND_STRUCT, BTFKIND_UNION,
              BTFKIND_ENUM, BTFKIND_ENUM64, BTFKIND_FLOAT,
              BTFKIND_DATASEC]

NO_VALID_NAME = [BTFKIND_PTR, BTFKIND_ARRAY,
                 BTFKIND_VOLATILE, BTFKIND_CONST,
                 BTFKIND_RESTRICT, BTFKIND_FUNC_PROTO]

BTFTYPE_TEMPLATE = "=III"
BTFTYPE = Struct(BTFTYPE_TEMPLATE)
BTFSIZE = calcsize(BTFTYPE_TEMPLATE)

BTFINT_TEMPLATE = "=I"
BTFINT = Struct(BTFINT_TEMPLATE)
BTFI_SIZE = calcsize(BTFINT_TEMPLATE)

BTFARRAY_TEMPLATE = "=III"
BTFARRAY = Struct(BTFARRAY_TEMPLATE)
BTFA_SIZE = calcsize(BTFARRAY_TEMPLATE)

BTFSTRUCT_TEMPLATE = "=III"
BTFSTRUCT = Struct(BTFSTRUCT_TEMPLATE)
BTFS_SIZE = calcsize(BTFSTRUCT_TEMPLATE)

BTFENUM_TEMPLATE = "=II"
BTFENUM = Struct(BTFENUM_TEMPLATE)
BTFE_SIZE = calcsize(BTFENUM_TEMPLATE)

BTFFP_TEMPLATE = "=II"
BTFFP = Struct(BTFFP_TEMPLATE)
BTFFP_SIZE = calcsize(BTFFP_TEMPLATE)

BTFVAR_TEMPLATE = "=I"
BTFVAR = Struct(BTFVAR_TEMPLATE)
BTFVAR_SIZE = calcsize(BTFVAR_TEMPLATE)

BTFSEC_TEMPLATE = "=III"
BTFSEC = Struct(BTFSEC_TEMPLATE)
BTFSEC_SIZE = calcsize(BTFSEC_TEMPLATE)

BTFDECL_TAG_TEMPLATE = "=I"
BTFDECL_TAG = Struct(BTFDECL_TAG_TEMPLATE)
BTFDECL_TAG_SIZE = calcsize(BTFDECL_TAG_TEMPLATE)

BTFE64_TEMPLATE = "=III"
BTFE64 = Struct(BTFE64_TEMPLATE)
BTFE64_SIZE = calcsize(BTFE64_TEMPLATE)

# We need to disable this because of using a class per
# BTF rtype. While this results in rather ugly python,
# it may prove useful later when we add parsing, templates,
# etc.

# pylint: disable=too-few-public-methods
# pylint: disable=too-many-arguments
# pylint: disable=unused-variable

REF_TYPES = [BTFKIND_CONST, BTFKIND_VOLATILE, BTFKIND_RESTRICT,
             BTFKIND_VAR, BTFKIND_DECL_TAG, BTFKIND_TYPE_TAG,
             BTFKIND_PTR]

QUAL_TYPES = [BTFKIND_CONST, BTFKIND_VOLATILE, BTFKIND_RESTRICT,
             BTFKIND_VAR, BTFKIND_DECL_TAG, BTFKIND_TYPE_TAG]


class BTFBase():
    '''Class representing a single BTF Record'''
    # pylint: disable=too-many-instance-attributes
    def __init__(self, kind=None, vlen=0, kind_flag=False,
                 size_or_type=0, name=None, name_off=0, btf=None):

        self.data = {}
        if btf is not None:
            self.elbufpos = btf.buffpos
        else:
            self.ebufpos = 0
        self.data["tid"] = kind
        self.bufsize = BTFSIZE
        self.btf = btf
        self.has_size = False
        self.data["name"] = None
        if not kind in NO_VALID_NAME:
            if name is not None:
                self.data["name"] = name
            else:
                if name_off > 0:
                    self.data["name"] = btf.resolve_str(name_off)

        self.name_off = name_off
        self.vlen = vlen
        self.tid_flag = kind_flag
        if self.tid in KS_IS_SIZE:
            self.has_size = True
            self.data["size"] = size_or_type
        else:
            self.data["type_id"] = size_or_type

        if IS_64:
            self.template = "Q"
        else:
            self.template = "I"


    def set_size(self, arg):
        '''Size setter'''
        self.data["size"] = arg

    def set_type(self, arg):
        '''Type setter'''
        self.data["type"] = arg

    def set_name(self, arg):
        '''Name setter'''
        self.data["name"] = arg

    def set_tid(self, arg):
        '''Tid setter'''
        self.data["tid"] = arg

    def set_template(self, arg):
        '''Template setter'''
        self.data["template"] = arg

    def get_size(self):
        '''Size getter'''
        return self.data["size"]

    def get_type(self):
        '''Type getter'''
        return self.data["type"]

    def get_name(self):
        '''Name getter'''
        return self.data["name"]

    def get_tid(self):
        '''Tid getter'''
        return self.data["tid"]

    def get_template(self):
        '''Template getter'''
        return self.data["template"]


    size = property(get_size, set_size)
    rtype = property(get_type, set_type)
    name = property(get_name, set_name)
    tid = property(get_tid, set_tid)
    template = property(get_template, set_template)


    def __repr__(self):
        '''Printable representation'''

        if self.tid in REF_TYPES and (not self.rtype.tid in REF_TYPES):
            return "".format({"name":self.rtype.name})
        return "{}".format(self.data)

    def resolve_types(self):
        '''resolve_type refereces'''
        try:
            if not self.has_size:
                self.rtype = self.btf.resolve_type(self.data["type_id"])
                del(self.data["type_id"])
        except IndexError:
            pass
        except KeyError:
            pass


    def generate_template(self):
        '''Generate parsing template
        By default treat everything as an unsigned int, descendants will override
        if needed'''

        if self.template is not None:
            return self.template

        if IS_64:
            fmat = "Q"
        else:
            fmat = "I"

        if self.tid in QUAL_TYPES:
            self.template = self.rtype.generate_template()
        else:
            self.template = fmat

class BTFGeneric(BTFBase):
    '''Generic (no records) init'''
    def __init__(self, kind=None, vlen=0, kind_flag=False,
                 size_or_type=0, name=None, name_off=0, btf=None):
        super().__init__(kind=kind, vlen=vlen, kind_flag=kind_flag,
                         size_or_type=size_or_type, name=name, name_off=name_off,
                         btf=btf)

class BTFInt(BTFBase):
    '''Int init'''
    def __init__(self, kind=None, vlen=0, kind_flag=False,
                 size_or_type=0, name=None, name_off=0, btf=None):

        super().__init__(kind=kind, vlen=vlen, kind_flag=kind_flag,
                         size_or_type=size_or_type, name=name, name_off=name_off,
                         btf=btf)

        loc = btf.buffpos + self.bufsize
        self.bufsize += BTFI_SIZE

        intprops = BTFINT.unpack(btf.buff[loc : loc + BTFI_SIZE])

        self.data["int_encoding"] = (intprops[0] & 0x0f000000) >> 24
        self.data["int_offset"] = (intprops[0] & 0x00ff0000) >> 16
        self.data["int_bits"] = intprops[0] & 0x000000ff

        if self.data["int_offset"] > 0:
            self.template = None
        else:
            if self.data["int_bits"] == 8:
                self.template = 'b'
            elif self.data["int_bits"] == 16:
                self.template = 'h'
            elif self.data["int_bits"] == 32:
                self.template = 'i'
            elif  self.data["int_bits"] == 64:
                self.template = 'q'

            if self.data["int_encoding"] & (1 << 0) == 0:
                self.template = self.template.capitalize()



class BTFArray(BTFBase):
    '''ARRAY init'''
    def __init__(self, kind=None, vlen=0, kind_flag=False,
                 size_or_type=0, name=None, name_off=0, btf=None):

        super().__init__(kind=kind, vlen=vlen, kind_flag=kind_flag,
                         size_or_type=size_or_type, name=name, name_off=name_off,
                         btf=btf)

        loc = btf.buffpos + self.bufsize
        self.bufsize += BTFA_SIZE

        (artype, index_type, nelems) = BTFARRAY.unpack(btf.buff[loc : loc + BTFA_SIZE])
        self.data["array_type_id"] = artype
        self.data["index_type_id"] = index_type
        self.data["nelems"] = nelems

    def resolve_types(self):
        '''Resolve type references'''

        self.data["array_type"] = self.btf.resolve_type(self.data["array_type_id"])
        self.data["index_type"] = self.btf.resolve_type(self.data["index_type_id"])
        del(self.data["array_type_id"])
        del(self.data["index_type_id"])

    def generate_template(self):
        '''Generate template'''

        if self.data["array_type"] is None:
            return
        try:
            self.data["array_type"].generate_template()
            temp = self.data["array_type"].template
            if temp is None:
                return
            self.template = ""
            for count in range(0, self.data["nelems"]):
                self.template += temp
        except AttributeError:
            pass

class BTFStruct(BTFBase):
    '''Struct/Union init'''
    def __init__(self, kind=None, vlen=0, kind_flag=False,
                 size_or_type=0, name=None, name_off=0, btf=None):
        super().__init__(kind=kind, vlen=vlen, kind_flag=kind_flag,
                         size_or_type=size_or_type,
                         name=name, name_off=name_off, btf=btf)

        loc = btf.buffpos + self.bufsize
        self.bufsize += BTFS_SIZE * self.vlen

        self.data["members"] = []
        for count in range(0, self.vlen):
            (name_off, stype, offset) = BTFSTRUCT.unpack(btf.buff[loc:loc + BTFS_SIZE])
            self.data["members"].append({
                "name" : self.btf.resolve_str(name_off),
                "type_id" : stype,
                "offset" : offset
            })
            loc += BTFS_SIZE

    def resolve_types(self):
        '''Resolve type references'''
        try:
            for member in self.data["members"]:
                member["type"] = self.btf.resolve_type(member["type_id"])
                del(member["type_id"])
        except KeyError:
            print("Invalid struct/union: {}".format(self.name))

    def generate_template(self):
        '''Generate template'''

        fmat = ""
        if self.tid == BTFKIND_STRUCT and len(self.data["members"]) > 0:
            try:
                for item in self.data["members"]:
                    fmat += item["type"].generate_template()
            except TypeError:
                fmat = None
        self.template = fmat


class BTFEnum(BTFBase):
    '''Enum Init'''
    def __init__(self, kind=None, vlen=0, kind_flag=False, size_or_type=0,
                 name=None, name_off=0, btf=None):
        super().__init__(kind=kind, vlen=vlen, kind_flag=kind_flag,
                         size_or_type=size_or_type, name=name, name_off=name_off,
                         btf=btf)

        loc = btf.buffpos + self.bufsize
        self.bufsize += BTFE_SIZE * self.vlen

        self.data["values"] = []
        for count in range(0, self.vlen):
            (name_off, val) = BTFENUM.unpack(btf.buff[loc:loc + BTFE_SIZE])
            self.data["values"].append({
                "name" : self.btf.resolve_str(name_off),
                "value" : val
            })
            loc += BTFE_SIZE


class BTFFuncProto(BTFBase):
    '''Func proto init'''
    def __init__(self, kind=None, vlen=0, kind_flag=False,
                 size_or_type=0, name=None, name_off=0, btf=None):
        super().__init__(kind=kind, vlen=vlen, kind_flag=kind_flag,
                         size_or_type=size_or_type, name=name, name_off=name_off, btf=btf)

        loc = btf.buffpos + self.bufsize
        self.bufsize += BTFFP_SIZE * self.vlen


        self.data["params"] = []
        for count in range(0, self.vlen):
            (name_off, ftype) = BTFFP.unpack(btf.buff[loc:loc + BTFFP_SIZE])
            self.data["params"].append({
                "name" : self.btf.resolve_str(name_off),
                "type_id" : ftype
            })
            loc += BTFFP_SIZE


    def resolve_types(self):
        '''Resolve type references'''

        for member in self.data["params"]:
            member["type"] = self.btf.resolve_type(member["type_id"])
            del(member["type_id"])


class BTFVar(BTFBase):
    '''Var init'''
    def __init__(self, kind=None, vlen=0, kind_flag=False,
                 size_or_type=0, name=None, name_off=0, btf=None):

        super().__init__(kind=kind, vlen=vlen, kind_flag=kind_flag,
                         size_or_type=size_or_type, name=name, name_off=name_off,
                         btf=btf)

        loc = btf.buffpos + self.bufsize

        self.bufsize += BTFVAR_SIZE

        (linkage) = BTFVAR.unpack(btf.buff[loc:loc + BTFVAR_SIZE])
        self.data["linkage"] = linkage

class BTFDataSec(BTFBase):
    '''Datasec init'''
    def __init__(self, kind=None, vlen=0, kind_flag=False,
                 size_or_type=0, name=None, name_off=0, btf=None):
        super().__init__(kind=kind, vlen=vlen, kind_flag=kind_flag,
                         size_or_type=size_or_type, name=name, name_off=name_off,
                         btf=btf)

        loc = btf.buffpos + self.bufsize
        self.bufsize += BTFSEC_SIZE * self.vlen

        self.data["members"] = []

        for count in range(0, self.vlen):
            (stype, offset, size) = BTFSEC.unpack(btf.buff[loc:loc + BTFSEC_SIZE])
            self.data["members"].append({
                "type_id" : stype,
                "offset" : offset,
                "size" : size
            })
            loc += BTFSEC_SIZE

    def resolve_types(self):
        '''Resolve type references'''

        for member in self.data["members"]:
            member["type"] = self.btf.resolve_type(member["type_id"])
            del(member["type_id"])

class BTFEnum64(BTFBase):
    '''Enum 64 init'''
    def __init__(self, kind=None, vlen=0, kind_flag=False, size_or_type=0,
                 name=None, name_off=0, btf=None):
        super().__init__(kind=kind, vlen=vlen, kind_flag=kind_flag,
                         size_or_type=size_or_type, name=name, name_off=name_off,
                         btf=btf)

        loc = btf.buffpos + self.bufsize
        self.bufsize += BTFE64_SIZE * self.vlen

        self.data["values"] = []

        for count in range(0, self.vlen):
            (name_off, lo32, hi32) = BTFE64.unpack(btf.buff[loc:loc + BTFE64_SIZE])
            self.data["values"].append({
                "name" : self.btf.resolve_str(name_off),
                "value" : lo32 + (hi32 << 32)
            })
            loc += BTFE64_SIZE

class BTFDeclTag(BTFBase):
    '''Tag Init'''
    def __init__(self, kind=None, vlen=0, kind_flag=False,
                 size_or_type=0, name=None, name_off=0, btf=None):
        super().__init__(kind=kind, vlen=vlen, kind_flag=kind_flag,
                         size_or_type=size_or_type, name=name, name_off=name_off,
                         btf=btf)

        loc = btf.buffpos + self.bufsize
        self.bufsize += BTFDECL_TAG_SIZE

        (idx) = BTFDECL_TAG.unpack(btf.buff[loc:loc + BTFDECL_TAG_SIZE])
        self.data["idx"] = idx

BASE_TYPES = [
    BTFGeneric(kind=BTFKIND_VOID, name="void"),
    BTFGeneric(kind=BTFKIND_INT, name="int"),
    BTFGeneric(kind=BTFKIND_PTR, name="ptr"),
    BTFGeneric(kind=BTFKIND_ARRAY, name="array"),
    BTFGeneric(kind=BTFKIND_STRUCT, name="struct"),
    BTFGeneric(kind=BTFKIND_STRUCT, name="union"),
    BTFGeneric(kind=BTFKIND_ENUM, name="enum"),
    BTFGeneric(kind=BTFKIND_FWD, name="fwd"),
    BTFGeneric(kind=BTFKIND_TYPEDEF, name="typedef"),
    BTFGeneric(kind=BTFKIND_VOLATILE, name="volatile"),
    BTFGeneric(kind=BTFKIND_CONST, name="const"),
    BTFGeneric(kind=BTFKIND_RESTRICT, name="restrict"),
    BTFGeneric(kind=BTFKIND_FUNC, name="func"),
    BTFGeneric(kind=BTFKIND_FUNC_PROTO, name="func_proto"),
    BTFGeneric(kind=BTFKIND_VAR, name="var"),
    BTFGeneric(kind=BTFKIND_DATASEC, name="datasec"),
    BTFGeneric(kind=BTFKIND_FLOAT, name="float"),
    BTFGeneric(kind=BTFKIND_DECL_TAG, name="decl_tag"),
    BTFGeneric(kind=BTFKIND_TYPE_TAG, name="type_tag"),
    BTFGeneric(kind=BTFKIND_ENUM64, name="enum64")
]

JUMP_TABLE = {
    BTFKIND_INT: BTFInt,
    BTFKIND_ARRAY: BTFArray,
    BTFKIND_STRUCT: BTFStruct,
    BTFKIND_UNION: BTFStruct,
    BTFKIND_ENUM: BTFEnum,
    BTFKIND_FUNC_PROTO: BTFFuncProto,
    BTFKIND_VAR: BTFVar,
    BTFKIND_DATASEC: BTFDataSec,
    BTFKIND_DECL_TAG: BTFDeclTag,
    BTFKIND_ENUM64: BTFEnum64
}

class BTFBlob():
    '''A blob of BTF Data'''
    # pylint: disable=too-many-instance-attributes

    def __init__(self, buff):
        self.buff = buff
        (magic, version, flags, self.hdr_len, self.type_off,
         self.type_len, self.str_off, self.str_len) = \
            BTFHEADER.unpack(buff[0:BTFHEADER_SIZE])
        self.elements = []
        self.buffpos = self.type_off + BTFHEADER_SIZE

    def resolve_str(self, index):
        '''Resolve string from string table'''
        res = None
        start = self.str_off + BTFHEADER_SIZE + index
        try:
            for pos in range(start, len(self.buff)):
                if self.buff[pos] == 0:
                    res = str(self.buff[start:pos], encoding="ascii")
                    break
        except IndexError:
            pass
        return res

    def resolve_type(self, index):
        '''Resolve rtype from rtype table'''
        try:
            return self.elements[index - 1] 
        except IndexError:
            return BASETYPES[0]

    def parse(self):
        '''Parse blob'''
        while self.buffpos < self.type_off + self.type_len:
            (name_off, info, size_or_type) = \
                BTFTYPE.unpack(self.buff[self.buffpos:self.buffpos + BTFSIZE])
            vlen = info & 0xFFFF
            kind = (info & 0x1F000000) >> 24
            kind_flag = not (info & 0x10000000) == 0
            rec = None
            try:
                rec = JUMP_TABLE[kind](kind=kind,
                                       vlen=vlen,
                                       kind_flag=kind_flag,
                                       size_or_type=size_or_type,
                                       name_off=name_off,
                                       btf=self)
            except KeyError:
                if kind > 0:
                    rec = BTFGeneric(kind=kind,
                                     vlen=vlen,
                                     kind_flag=kind_flag,
                                     size_or_type=size_or_type,
                                     name_off=name_off,
                                     btf=self)
                else:
                    rec = BTFGENERIC[0]
            self.elements.append(rec)
            self.buffpos += rec.bufsize

        for item in self.elements:
            item.resolve_types()

    def find_by_name(self, name):
        '''Find a type by name'''
        compare = name.encode("ascii")
        for element in self.elements:
            if element.name == compare:
                return element
        return None

    def __repr__(self):
        '''Print BTF data'''
        ret = ""
        for item in self.elements:
            if item.tid != 0 and item.tid != BTFKIND_FUNC:
                ret += "{}\n".format(item)
        return ret
