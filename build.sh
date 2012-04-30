#!/bin/sh
gcc -ggdb -Wall -D_FILE_OFFSET_BITS=64 `pkg-config fuse MagickWand libexif --cflags --libs` fusexmp.c -o fusexmp&&
fusermount -u mnt&&
./fusexmp mnt&&
ls -fl mnt
