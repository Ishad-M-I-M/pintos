#!/bin/bash

cmd="$1"

case $cmd in

    1)
        make clean
        make
        pintos-mkdisk build/filesys.dsk --filesys-size=2
        pintos -- -f -q
        pintos -p ../examples/echo -a echo -- -q
        pintos –v -- run 'echo x'
        ;;
    1-d)
        make clean
        make
        pintos-mkdisk build/filesys.dsk --filesys-size=2
        pintos -- -f -q
        pintos -p ../examples/echo -a echo -- -q
        pintos –v --gdb -- run 'echo x'
        ;;
    2)  #arg testcases
        make clean
        make
        make build/tests/userprog/args-none.result
        make build/tests/userprog/args-single.result
        make build/tests/userprog/args-multiple.result
        make build/tests/userprog/args-many.result
        make build/tests/userprog/args-dbl-space.result
        ;;
    3) #to debug read-bad-ptr
        make clean
        make
        pintos -v -k -T 60 --qemu  --filesys-size=2 -p build/tests/userprog/read-bad-ptr -a read-bad-ptr -p ../tests/userprog/sample.txt -a sample.txt --gdb -- -q  -f run read-bad-ptr 
        ;;
esac