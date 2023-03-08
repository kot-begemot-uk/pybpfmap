

all:
	python3 setup.py build_ext -i 

test:	all
	nosetests3 tests/test_encode_decode.py

clean:
	rm -fr *.so bpfrecord.c
