/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  PUT IN THE FUSE example directory

  gcc -Wall `pkg-config fuse MagickWand --cflags --libs` fusexmp.c -o fusexmp

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

#include <stdlib.h>
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <wand/MagickWand.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/stat.h>


#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#define ThrowWandException(wand) \
{ \
  char \
    *description; \
 \
  ExceptionType \
    severity; \
 \
  description=MagickGetException(wand,&severity); \
  (void) fprintf(stderr,"%s %s %lu %s\n",GetMagickModule(),description); \
  description=(char *) MagickRelinquishMemory(description); \
  exit(-1); \
}

#define DEBUG 1
typedef char path_t[256];

struct perf{
	time_t load_time; //time between mount & 'ready to use'
	time_t close_time;
	time_t read_time;
	time_t convert_time;
};

struct sort_directoryEntry {
	struct dirent *entries;
	off_t size;
	int allocated;
};

typedef struct sort_directoryEntry sort_dirent;

path_t basedir;



void logging(const char* entry, char *title){

	FILE *log;
	struct timeval time;
	gettimeofday(&time, NULL);

	log = fopen("/tmp/ypfs.log", "a");

	fprintf(log, "%ld:%ld \t %s \t %s\n", time.tv_sec, time.tv_usec, title, entry);

	fclose(log);
	return;
}

void loggingInt(int a, char *title){
	FILE *log;
	struct timeval time;
	gettimeofday(&time, NULL);

	log = fopen("/tmp/ypfs.log", "a");

	fprintf(log, "%ld:%ld \t %s \t %i\n", time.tv_sec, time.tv_usec, title, a);

	fclose(log);
	return;
}

void loggingList(char** entry, char *title){

	FILE *log;
	struct timeval time;
	int i = 1;
	gettimeofday(&time, NULL);

	log = fopen("/tmp/ypfs.log", "a");
	fprintf(log, "%ld:%ld \t %s \t %s\n", time.tv_sec, time.tv_usec, title, entry[0]);
	for(;i < sizeof(entry)/sizeof(char); i++){
		fprintf(log, "\t \t \t %s\n",entry[i]);
	}
	fclose(log);
	return;
}

void* fxp_init(struct fuse_conn_info *conn){
	logging("", "init");

	return conn;
}

void split_path(char* path, char** splitpath){
	char* token = strtok(path, "/");
	logging(path, "splitpath");
	while(token != NULL){
		*splitpath = token;
		splitpath++;
		token = strtok(path, "/");
	}
	logging(path, "path split in");
	loggingList(splitpath, "path split out");
	return;
}

char * get_full_path(char* fullpath, const char* localpath){
	sprintf(fullpath, "%s/%s", basedir,localpath);
	logging(localpath, "get full path in");
	logging(fullpath, "get full path out");
	return fullpath;
}

void get_basedir(){
	struct passwd pass;
	struct passwd *result;
	path_t buf;

	getpwuid_r(getuid(), &pass, buf, 256, &result);
	strcpy(basedir, pass.pw_dir);
	logging(basedir, "pass.pw_dir in get base dir");
	strcat(basedir, "/.ypfs");
	logging(basedir, "concat /.ypfs");

	if(opendir(basedir) == NULL){
		logging("","made base dir");
		mkdir(basedir, S_IRUSR | S_IWUSR);
	}
	logging(basedir, "base dir");
	return;
}


static int convert(const path_t path){ //TODO:FINISH ME
	//this is used when we already know we don't have the format the user wants
	char *path_extension = strrchr(path, (int)"."); //points to the "."
	MagickBooleanType status;
	MagickWand *magick_wand;


	MagickWandGenesis();
	magick_wand = NewMagickWand();
	status = MagickReadImage(magick_wand,path);

	if (status == MagickFalse){
		ThrowWandException(magick_wand);
	}
	return 0;
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res;
	path_t fullpath;
	get_full_path(fullpath, path);

	logging(fullpath,"getAttr");
	res = lstat(fullpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	logging(path,"access");
	int res;
	path_t fullpath;
	get_full_path(fullpath, path);
	res = access(fullpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	logging(path, "readlink");
	int res;
	path_t fullpath;
	get_full_path(fullpath, path);
	res = readlink(fullpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}

time_t get_mtime(const char *path)
{
	logging(path,"mtime");
    struct stat statbuf;
	path_t fullpath;
	get_full_path(fullpath, path);
    if (stat(fullpath, &statbuf) == -1) {
        perror(fullpath);
        exit(1);
    }
    return statbuf.st_mtime; //or st_mtim
}
// use this to get the file dates
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

int comparatorOne(struct tm a, struct tm b){
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

int comparatorTwo(struct tm a, time_t b){
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

int comparatorThree(time_t a, time_t b){
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


int compare(const void *a, const void *b){
	logging("", "compare");
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
		logging(dir1->d_name,"no exif one");
		filetime1 = get_mtime(dir1->d_name);
	}
	if(second){
		date2 = exif_content_get_entry(first->ifd[EXIF_IFD_0], EXIF_TAG_DATE_TIME);
		exif_entry_get_value(date1, buff, sizeof(buff));
		strptime(buff, "%Y:%m:%d %H:%M:%S", &file_time2);
	}
	else{
		filetime2 = get_mtime(dir2->d_name);
		logging(dir2->d_name,"no exif two");
	}

	//compare times
	if(first && second){
		logging("","both exif data");
		compareTo = comparatorOne(file_time1, file_time2);
	}
	else if(first){
		logging("","first exif data");
		compareTo = comparatorTwo(file_time1, filetime2);
	}
	else if(second){
		logging("","2nd exif data");
		compareTo = -comparatorTwo(file_time2, filetime1);
	}
	else{
		logging("","no exif data");
		compareTo = comparatorThree(filetime1, filetime2);
	}

	return compareTo;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fileInfo)
{
	logging(path,"readdir");
	DIR *dirStream;
	sort_dirent sortDir;
	struct dirent *result;
	void* reAllocation;
	int i = 0;

	(void) offset;
	(void) fileInfo;
	path_t fullpath;
	get_full_path(fullpath, path);

	dirStream = opendir(fullpath);

	if (dirStream == NULL){
		return -errno;
	}

	//increase initial allocation of entries, could change performance
	sortDir.entries = (struct dirent*) malloc(10 * (sizeof(struct dirent)));
	if(sortDir.entries == NULL){
		return -ENOMEM;
	}
	sortDir.allocated = 10;
	sortDir.size = 0;

	//while readdir_r returns 0, i.e. success
	while (!(readdir_r(dirStream, &sortDir.entries[sortDir.size], &result)) && result!=NULL) {

		sortDir.size++;

		if(DEBUG){
			printf("sort.Dir increased to %d\n",(int)sortDir.size);
		}


		//increases size of entries
		if(sortDir.size >= sortDir.allocated)
		{
			loggingInt(sortDir.size,"reAlloc size");
			loggingInt(sortDir.allocated,"reAlloc allocation");

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
	logging(path,"mknod");
	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	path_t fullpath;
	get_full_path(fullpath, path);


	if (S_ISREG(mode)) {
		res = open(fullpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(fullpath, mode);
	else
		res = mknod(fullpath, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;
	path_t fullpath;
	get_full_path(fullpath, path);

	res = mkdir(fullpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;
	path_t fullpath;
	get_full_path(fullpath, path);

	res = unlink(fullpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;
	path_t fullpath;
	get_full_path(fullpath, path);

	res = rmdir(fullpath);
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
	path_t fullpath;
	get_full_path(fullpath, path);

	res = chmod(fullpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	path_t fullpath;
	get_full_path(fullpath, path);

	res = lchown(fullpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	logging(path,"truncate");
	int res;
	path_t fullpath;
	get_full_path(fullpath, path);

	res = truncate(fullpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];
	path_t fullpath;
	get_full_path(fullpath, path);

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(fullpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	logging(path, "open");
	int res;
	path_t fullpath;
	get_full_path(fullpath, path);

	res = open(fullpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

int try_different_extension(const char *broken_path){ //path should already be properly qualified
	logging(broken_path,"try extension");
	int out = -1, i = 0;
	char *path = NULL;
	strcpy(path, broken_path);

	char *path_extension = strrchr(path, (int)"."); //points to the dot
	char *formats[5] = {".jpg",".png",".bmp",".gif",".tiff"};
	for(; i<sizeof(formats)/sizeof(char); i++){
		if (!strcmp(path_extension,formats[i])){
			logging(formats[i], "ext rejected");
			continue;
		}
		else{
			logging(formats[i], "ext attempt");
			strcpy(path_extension, formats[i]);
			out = open(path, O_RDONLY);
			if(out){
				logging(formats[i], "ext found");
				break;
			}
		}
	}

	return out;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	logging(path, "read");
	int filedescriptor;
	int res;

	(void) fi;

	path_t fullpath;
	get_full_path(fullpath, path);

	filedescriptor = open(fullpath, O_RDONLY);
	if (filedescriptor == -1){ //no file at that path
		filedescriptor = try_different_extension(fullpath);
		if(filedescriptor){//path found with different extension
			convert(fullpath);
		}
	}

	if(filedescriptor == -1){
		return -errno;
	}


	res = pread(filedescriptor, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(filedescriptor);
	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	logging(path, "write");
	int fd;
	int res;

	(void) fi;
	path_t fullpath;
	get_full_path(fullpath, path);

	fd = open(fullpath, O_WRONLY);
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
	logging(path, "statfs");
	int res;
	path_t fullpath;

	get_full_path(fullpath, path);

	logging(fullpath, "statfs");
	res = statvfs(fullpath, stbuf);

	loggingInt(res, "statvfs return");
	if (res == -1)
		loggingInt(-errno, "statfs fail");
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
	path_t fullpath;
	get_full_path(fullpath, path);

	int res = lsetxattr(fullpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	path_t fullpath;
	get_full_path(fullpath, path);

	int res = lgetxattr(fullpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	path_t fullpath;
	get_full_path(fullpath, path);

	int res = llistxattr(fullpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	path_t fullpath;
	get_full_path(fullpath, path);

	int res = lremovexattr(fullpath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
	.init		= fxp_init,
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
	logging("RUNTIME----------","---------NEW");
	umask(0);
//	basedir = get_current_dir_name();
	get_basedir();
	logging("", "before fuse_main");
	return fuse_main(argc, argv, &xmp_oper, NULL);
}
