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
esac