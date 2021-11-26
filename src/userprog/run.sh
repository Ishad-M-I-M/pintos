#!/bin/bash

make clean
make
pintos-mkdisk build/filesys.dsk --filesys-size=2
pintos -- -f -q
pintos -p ../examples/echo -a echo -- -q
pintos –v -- run 'echo x'
