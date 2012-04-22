FUSE has been installed on the Hack Factor, `factor007`.

You can compile fusexmp with:

    $ gcc -Wall `pkg-config fuse --cflags --libs` fusexmp.c -o fusexmp

And then mount it with:

    $ ./fusexmp <dir> -o nonempty

And unmount it:

    $ fusermount -u <dir>
