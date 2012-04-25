/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  PUT IN THE FUSE example directory

  gcc -Wall `pkg-config fuse --cflags --libs` fusexmp.c -o fusexmp
*/

#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include <libexif/exif-loader.h>

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#define DEBUG 1
typedef char path_t[256];


struct sort_directoryEntry {
	struct dirent *entries;
	off_t size;
	int allocated;
};

typedef struct sort_directoryEntry sort_dirent;

path_t basedir;


void split_path(char* path, char** splitpath)
{
	char* token = strtok(path, "/");
	while(token != NULL){
		*splitpath = token;
		splitpath++;
		token = strtok(path, "/");
	}

	return;
}

void get_full_path(const char* localpath, char* fullpath)
{
	sprintf(fullpath, "%s/%s", basedir, localpath);
}

static void get_basedir()
{
	struct passwd pass;
	struct passwd *result;
	path_t buf;

	getpwuid_r(getuid(), &pass, buf, 256, &result);
	strcpy(basedir, pass.pw_dir);
	strcat(basedir, "/.ypfs");
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res;

	res = lstat(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	int res;

	res = access(path, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;
	path_t real;
	res = readlink(path, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}

time_t get_mtime(const char *path)
{
    struct stat statbuf;
    if (stat(path, &statbuf) == -1) {
        perror(path);
        exit(1);
    }
    return statbuf.st_mtim;
}
//
//ExifEntry *date1, *date2;
//char buff[1024], year[1024], month[1024], name1[2048], name2[2048];
//struct tm file_time;
//ExifData *first = exif_data_new_from_file(dir1->d_name);
//ExifData *second = exif_data_new_from_file(dir2->d_name);
//
//
//if(first){ //has exif data
//	date1 = exif_content_get_entry(first->ifd[EXIF_IFD_0], EXIF_TAG_DATE_TIME);
//	exif_entry_get_value(date1, buff, sizeof(buff));
//	strptime(buff, "%Y:%m:%d %H:%M:%S", &file_time);
//	strftime(year, 1024, "%Y", &file_time);
//	strftime(month, 1024, "%B", &file_time);
//	//get more detailed time for comparison
//	sprintf(name1, "/%s/%s/%s", year, month, dir1->d_name);
//
//}
//else{ //no exif data
//	get_mtime(dir1->d_name);



static int compare(const void *a, const void *b){
	int compareTo = 0;
	struct dirent *dir1 = (struct dirent *)a;
	struct dirent *dir2 = (struct dirent *)b;

	ExifEntry *date1, *date2;
	char buff[1024], year[1024], month[1024];
	struct tm file_time1, file_time2;
	time_t filetime1, filetime2;

	ExifData *first = exif_data_new_from_file(dir1->d_name);
	ExifData *second = exif_data_new_from_file(dir2->d_name);

	//get time of file, either exif or mtime
	if(first && second){ //has exif data
		date1 = exif_content_get_entry(first->ifd[EXIF_IFD_0], EXIF_TAG_DATE_TIME);
		exif_entry_get_value(date1, buff, sizeof(buff));
		strptime(buff, "%Y:%m:%d %H:%M:%S", &file_time1);
	}
	else{ //no exif data
		filetime1 = get_mtime(dir1->d_name);
	}
	if(second){
		date2 = exif_content_get_entry(first->ifd[EXIF_IFD_0], EXIF_TAG_DATE_TIME);
		exif_entry_get_value(date1, buff, sizeof(buff));
		strptime(buff, "%Y:%m:%d %H:%M:%S", &file_time2);
	}
	else{
		filetime2 = get_mtime(dir2->d_name);
	}

	//compare times
	if(first && second){
		compareTo = comparator1(file_time1, file_time2, 0);
	}
	else if(first){
		compareTo = comparator2(file_time1, filetime2);
	}
	else if(second){
		compareTo = comparator2(file_time2, filetime1);
	}
	else{
		compareTo = comparator3(filetime1, filetime2);
	}
	return compareTo;
}

int comparator1(struct tm a, struct tm b){
	int compareTo = 0;
	time_t since_epoch1 = mktime(&a);
	time_t since_epoch2 = mktime(&b);
	if(since_epoch1 > since_epoch2){
		compareTo = 1;
	}
	else if(since_epoch1 < since_epoch2){
		compareTo = -1;
	}
	else if(since_epoch1 == since_epoch2){
			compareTo = 0;
	}
	return compareTo;
}

int compartor2(struct tm a, time_t b){
	int compareTo = 0;
	time_t since_epoch = mktime(&a);
	if(since_epoch > b){
		compareTo = 1;
	}
	else if(since_epoch < b){
		compareTo = -1;
	}
	else if(since_epoch == b){
			compareTo = 0;
	}
	return compareTo;
}

int comparator3(time_t a, time_t b){
	int compareTo = 0;
	if (a>b){
		compareTo = 1;
	}
	else if(a < b){
		compareTo = -1;
	}
	else{
		compareTo = 0;
	}
	return compareTo;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fileInfo)
{
	DIR *dirStream;
	sort_dirent sortDir;
	struct dirent *result;
	void* reAllocation;
	int i = 0;

	(void) offset;
	(void) fileInfo;

	dirStream = opendir(path);

	if (dirStream == NULL){
		return -errno;
	}

	//increase initial allocation of entries, could change performance
	sortDir.entries = (struct dirent*) malloc((sizeof(struct dirent))*10);
	if(sortDir.entries == NULL){
		return -ENOMEM;
	}
	sortDir.allocated = 10;

	//while readdir_r returns 0, i.e. success
	while (!(readdir_r(dirStream, &sortDir.entries[sortDir.size], &result))) {

		sortDir.size++;

		if(DEBUG){
			printf("sort.Dir increased to %d\n",(int)sortDir.size);
		}

		//increases size of entries
		if(sortDir.size >= sortDir.allocated)
		{
			int newsize = 2*sortDir.size;
			reAllocation = realloc(sortDir.entries, newsize * sizeof(struct dirent));
			if(reAllocation == NULL) {
				free(sortDir.entries);
				return -ENOMEM;
			}
			sortDir.entries = reAllocation;
			sortDir.allocated = newsize;
		}
	}

	//sort according to date taken or date created
	qsort(sortDir.entries, sortDir.size, sizeof(struct dirent), compare);

	//

	//fills the buffer with entries, in the order it receives them
	for(i = offset; i < sortDir.size; i++ ){
		struct stat fileAttr;
		memset(&fileAttr, 0, sizeof(fileAttr));
		fileAttr.st_ino = sortDir.entries[i].d_ino;
		fileAttr.st_mode = sortDir.entries[i].d_type << 12;

		if (filler(buf, sortDir.entries[i].d_name, &fileAttr, 0))
			break;
	}
	closedir(dirStream);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(path, mode);
	else
		res = mknod(path, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;

	res = mkdir(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;

	res = unlink(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;

	res = rmdir(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;

	res = chmod(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;

	res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	int res;

	res = truncate(path, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(path, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res;

	res = open(path, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;
	fd = open(path, O_RDONLY);
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;
	fd = open(path, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

	res = statvfs(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	int res = lsetxattr(path, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	int res = lgetxattr(path, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	int res = llistxattr(path, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	int res = lremovexattr(path, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.utimens	= xmp_utimens,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	umask(0);
	get_base_dir();
	return fuse_main(argc, argv, &xmp_oper, NULL);
}
