FUSE has been installed on the Hack Factor, `factor007`.

You can compile fusexmp with:

    gcc -Wall -D_FILE_OFFSET_BITS=64 `pkg-config fuse MagickWand libexif --cflags --libs` fusexmp.c -o fusexmp

	"-D_FILE..." was added at the behest of the compiler. your usage may vary
	
And then mount it with:

    $ ./fusexmp <dir> -o nonempty

And unmount it:

    $ fusermount -u <dir>
