

all:
	python3 setup.py build_ext -i 

test:	all
	PYTHONPATH=$(CURDIR)/../ nosetests3 tests/test_encode_decode.py tests/test_bpf_map.py tests/test_bpf_filtered_map.py

clean:
	rm -fr *.so bpfrecord.c map_types.c
