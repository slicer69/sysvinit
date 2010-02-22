/*
 * hddown.c	Find all disks on the system and
 *		shut them down.
 *
 * Copyright (C) 2003 Miquel van Smoorenburg.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */
char *v_hddown = "@(#)hddown.c  1.02  22-Apr-2003  miquels@cistron.nl";

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>

#ifdef __linux__

#include <sys/ioctl.h>
#include <linux/hdreg.h>
#include <linux/fs.h>

#ifndef USE_SYSFS
# define USE_SYSFS	1
#endif
#if defined(USE_SYSFS) && (USE_SYSFS == 1)
/*
 * sysfs part	Find all disks on the system, list out IDE and unmanaged
 *		SATA disks, flush the cache of those and shut them down.
 * Author:	Werner Fink <werner@suse.de>, 2007/06/12
 *
 */
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef WORDS_BIGENDIAN
#include <byteswap.h>
#endif

#define SYS_BLK		"/sys/block"
#define SYS_CLASS	"/sys/class/scsi_disk"
#define DEV_BASE	"/dev"
#define ISSPACE(c)	(((c)==' ')||((c)=='\n')||((c)=='\t')||((c)=='\v')||((c)=='\r')||((c)=='\f'))

/* Used in flush_cache_ext(), compare with <linux/hdreg.h> */
#define IDBYTES		512
#define MASK_EXT	0xE000		/* Bit 15 shall be zero, bit 14 shall be one, bit 13 flush cache ext */
#define TEST_EXT	0x6000

/* Maybe set in list_disks() and used in do_standby_disk() */
#define DISK_IS_IDE	0x00000001
#define DISK_IS_SATA	0x00000002
#define DISK_EXTFLUSH	0x00000004
#define DISK_REMOVABLE	0x00000008
#define DISK_MANAGED	0x00000010
#define DISK_FLUSHONLY	0x00000020

static char *strstrip(char *str);
static FILE *hdopen(const char* const format, const char* const name);
static int flush_cache_ext(const char *device);

/*
 *	Find all disks through /sys/block.
 */
static char *list_disks(DIR* blk, unsigned int* flags)
{
	struct dirent *d;

	while ((d = readdir(blk))) {
		(*flags) = 0;
		if (d->d_name[1] == 'd' && (d->d_name[0] == 'h' || d->d_name[0] == 's')) {
			char buf[NAME_MAX+1], lnk[NAME_MAX+1], *ptr;
			FILE *fp;
			int ret;

			fp = hdopen(SYS_BLK "/%s/removable", d->d_name);
			if ((long)fp <= 0) {
				if ((long)fp < 0)
					goto empty;	/* error */
				continue;		/* no entry `removable' */
			}

			ret = getc(fp);
			fclose(fp);

			if (ret != '0')
				(*flags) |= DISK_REMOVABLE;

			if (d->d_name[0] == 'h') {
				if ((*flags) & DISK_REMOVABLE)
					continue;	/* not a hard disk */

				(*flags) |= DISK_IS_IDE;
				if ((ret = flush_cache_ext(d->d_name))) {
					if (ret < 0)
						goto empty;
					(*flags) |= DISK_EXTFLUSH;
				}
				break;			/* old IDE disk not managed by kernel, out here */
			}

			ret = snprintf(buf, sizeof(buf), SYS_BLK "/%s/device", d->d_name);
			if ((ret >= (int)sizeof(buf)) || (ret < 0))
				goto empty;		/* error */

			ret = readlink(buf, lnk, sizeof(lnk));
			if (ret >= (int)sizeof(lnk))
				goto empty;		/* error */
			if (ret < 0) {
				if (errno != ENOENT)
					goto empty;	/* error */
				continue;		/* no entry `device' */
			}
			lnk[ret] = '\0';

			ptr = basename(lnk);
			if (!ptr || !*ptr)
				continue;		/* should not happen */

			fp = hdopen(SYS_CLASS "/%s/manage_start_stop", ptr);
			if ((long)fp <= 0) {
				if ((long)fp < 0)
					goto empty;	/* error */
			} else {
				ret = getc(fp);
				fclose(fp);

				if (ret != '0') {
					(*flags) |= DISK_MANAGED;
					continue;
				}
			}

			fp = hdopen(SYS_BLK "/%s/device/vendor", d->d_name);
			if ((long)fp <= 0) {
				if ((long)fp < 0)
					goto empty;	/* error */
				continue;		/* no entry `device/vendor' */
			}

			ptr = fgets(buf, sizeof(buf), fp);
			fclose(fp);
			if (ptr == (char*)0)
				continue;		/* should not happen */

			ptr = strstrip(buf);
			if (*ptr == '\0')
				continue;		/* should not happen */

			if (strncmp(buf, "ATA", sizeof(buf)) == 0) {
				if ((*flags) & DISK_REMOVABLE)
					continue;	/* not a hard disk */

				(*flags) |= (DISK_IS_IDE|DISK_IS_SATA);
				if ((ret = flush_cache_ext(d->d_name))) {
					if (ret < 0)
						goto empty;
					(*flags) |= DISK_EXTFLUSH;
				}
				break;			/* new SATA disk to shutdown, out here */
			}

			if (((*flags) & DISK_REMOVABLE) == 0)
				continue;		/* Seems to be a real SCSI disk */

			if ((ret = flush_cache_ext(d->d_name))) {
				if (ret < 0)
					goto empty;
				(*flags) |= DISK_EXTFLUSH;
			}
			break;				/* Removable disk like USB stick to shutdown */
		}
	}
	if (d == (struct dirent*)0)
		goto empty;
	return d->d_name;
empty:
	return (char*)0;
}

/*
 *	Put an IDE/SCSI/SATA disk in standby mode.
 *	Code stolen from hdparm.c
 */
static int do_standby_disk(char *device, unsigned int flags)
{
#ifndef WIN_STANDBYNOW1
#define WIN_STANDBYNOW1		0xE0
#endif
#ifndef WIN_STANDBYNOW2
#define WIN_STANDBYNOW2		0x94
#endif
#ifndef WIN_FLUSH_CACHE_EXT
#define WIN_FLUSH_CACHE_EXT	0xEA
#endif
#ifndef WIN_FLUSH_CACHE
#define WIN_FLUSH_CACHE		0xE7
#endif
	unsigned char flush1[4] = {WIN_FLUSH_CACHE_EXT,0,0,0};
	unsigned char flush2[4] = {WIN_FLUSH_CACHE,0,0,0};
	unsigned char stdby1[4] = {WIN_STANDBYNOW1,0,0,0};
	unsigned char stdby2[4] = {WIN_STANDBYNOW2,0,0,0};
	char buf[NAME_MAX+1];
	int fd, ret;

	ret = snprintf(buf, sizeof(buf), DEV_BASE "/%s", device);
	if ((ret >= (int)sizeof(buf)) || (ret < 0))
		return -1;

	if ((fd = open(buf, O_RDWR|O_NONBLOCK)) < 0)
		return -1;

	switch (flags & DISK_EXTFLUSH) {
	case DISK_EXTFLUSH:
		if ((ret = ioctl(fd, HDIO_DRIVE_CMD, &flush1)) == 0)
			break;
		/* Extend flush rejected, try standard flush */
	default:
		ret = ioctl(fd, HDIO_DRIVE_CMD, &flush2) &&
		      ioctl(fd, BLKFLSBUF);
		break;
	}

	if ((flags & DISK_FLUSHONLY) == 0x0) {
		ret = ioctl(fd, HDIO_DRIVE_CMD, &stdby1) &&
		      ioctl(fd, HDIO_DRIVE_CMD, &stdby2);
	}

	close(fd);

	if (ret)
		return -1;
	return 0;
}

/*
 *	List all disks and put them in standby mode.
 *	This has the side-effect of flushing the writecache,
 *	which is exactly what we want on poweroff.
 */
int hddown(void)
{
	unsigned int flags;
	char *disk;
	DIR *blk;

	if ((blk = opendir(SYS_BLK)) == (DIR*)0)
		return -1;

	while ((disk = list_disks(blk, &flags)))
		do_standby_disk(disk, flags);

	return closedir(blk);
}

/*
 *	List all disks and cause them to flush their buffers.
 */
int hdflush(void)
{
	unsigned int flags;
	char *disk;
	DIR *blk;

	if ((blk = opendir(SYS_BLK)) == (DIR*)0)
		return -1;

	while ((disk = list_disks(blk, &flags)))
		do_standby_disk(disk, (flags|DISK_FLUSHONLY));

	return closedir(blk);
}

/*
 * Strip off trailing white spaces
 */
static char *strstrip(char *str)
{
	const size_t len = strlen(str);
	if (len) {
		char* end = str + len - 1;
		while ((end != str) && ISSPACE(*end))
			end--;
		*(end + 1) = '\0';			/* remove trailing white spaces */
	}
	return str;
}

/*
 * Open a sysfs file without getting a controlling tty
 * and return FILE* pointer.
 */
static FILE *hdopen(const char* const format, const char* const name)
{
	char buf[NAME_MAX+1];
	FILE *fp = (FILE*)-1;
	int fd, ret;
	
	ret = snprintf(buf, sizeof(buf), format, name);
	if ((ret >= (int)sizeof(buf)) || (ret < 0))
		goto error;		/* error */

	fd = open(buf, O_RDONLY|O_NOCTTY);
	if (fd < 0) {
		if (errno != ENOENT)
			goto error;	/* error */
		fp = (FILE*)0;
		goto error;		/* no entry `removable' */
	}

	fp = fdopen(fd, "r");
	if (fp == (FILE*)0)
		close(fd);		/* should not happen */
error:
	return fp;
}

/*
 * Check IDE/(S)ATA hard disk identity for
 * the FLUSH CACHE EXT bit set.
 */
static int flush_cache_ext(const char *device)
{
#ifndef WIN_IDENTIFY
#define WIN_IDENTIFY		0xEC
#endif
	unsigned char args[4+IDBYTES];
	unsigned short *id = (unsigned short*)(&args[4]);
	char buf[NAME_MAX+1], *ptr;
	int fd = -1, ret = 0;
	FILE *fp;

	fp = hdopen(SYS_BLK "/%s/size", device);
	if ((long)fp <= 0) {
		if ((long)fp < 0)
			return -1;	/* error */
		goto out;		/* no entry `size' */
	}

	ptr = fgets(buf, sizeof(buf), fp);
	fclose(fp);
	if (ptr == (char*)0)
		goto out;		/* should not happen */

	ptr = strstrip(buf);
	if (*ptr == '\0')
		goto out;		/* should not happen */

	if ((size_t)atoll(buf) < (1<<28))
		goto out;		/* small disk */
		
	ret = snprintf(buf, sizeof(buf), DEV_BASE "/%s", device);
	if ((ret >= (int)sizeof(buf)) || (ret < 0))
		return -1;		/* error */

	if ((fd = open(buf, O_RDONLY|O_NONBLOCK)) < 0)
		goto out;

	memset(&args[0], 0, sizeof(args));
	args[0] = WIN_IDENTIFY;
	args[3] = 1;
	if (ioctl(fd, HDIO_DRIVE_CMD, &args))
		goto out;
#ifdef WORDS_BIGENDIAN
# if 0
	{
		const unsigned short *end = id + IDBYTES/2;
		const unsigned short *from = id;
		unsigned short *to = id;

		while (from < end)
			*to++ = bswap_16(*from++);
	}
# else
	id[83] = bswap_16(id[83]);
# endif
#endif
	if ((id[83] & MASK_EXT) == TEST_EXT)
		ret = 1;
out:
	if (fd >= 0)
		close(fd);
	return ret;
}
#else /* ! USE_SYSFS */
#define MAX_DISKS	64
#define PROC_IDE	"/proc/ide"
#define DEV_BASE	"/dev"

/*
 *	Find all IDE disks through /proc.
 */
static int find_idedisks(const char **dev, int maxdev, int *count)
{
	DIR *dd;
	FILE *fp;
	struct dirent *d;
	char buf[256];

	if ((dd = opendir(PROC_IDE)) == NULL)
		return -1;

	while (*count < maxdev && (d = readdir(dd)) != NULL) {
		if (strncmp(d->d_name, "hd", 2) != 0)
			continue;
		buf[0] = 0;
		snprintf(buf, sizeof(buf), PROC_IDE "/%s/media", d->d_name);
		if ((fp = fopen(buf, "r")) == NULL)
			continue;
		if (fgets(buf, sizeof(buf), fp) == 0 ||
		    strcmp(buf, "disk\n") != 0) {
			fclose(fp);
			continue;
		}
		fclose(fp);
		snprintf(buf, sizeof(buf), DEV_BASE "/%s", d->d_name);
		dev[(*count)++] = strdup(buf);
	}
	closedir(dd);

	return 0;
}

/*
 *	Find all SCSI/SATA disks.
 */
static int find_scsidisks(const char **dev, int maxdev, int *count)
{
	if (*count < maxdev) dev[(*count)++] = DEV_BASE "/sda";
	if (*count < maxdev) dev[(*count)++] = DEV_BASE "/sdb";
	if (*count < maxdev) dev[(*count)++] = DEV_BASE "/sdc";
	if (*count < maxdev) dev[(*count)++] = DEV_BASE "/sdd";
	if (*count < maxdev) dev[(*count)++] = DEV_BASE "/sde";
	if (*count < maxdev) dev[(*count)++] = DEV_BASE "/sdf";
	if (*count < maxdev) dev[(*count)++] = DEV_BASE "/sdg";
	if (*count < maxdev) dev[(*count)++] = DEV_BASE "/sdh";

	return 0;
}

/*
 *	Open the device node of a disk.
 */
static int open_disk(const char *device)
{
	return open(device, O_RDWR);
}

/*
 *	Open device nodes of all disks, and store the file descriptors in fds.
 *	This has to be done in advance because accessing the device nodes
 *	might cause a disk to spin back up.
 */
static int open_disks(const char **disks, int *fds, int count)
{
	int i;

	for (i = 0; i < count; i++)
		fds[i] = open_disk(disks[i]);

	return 0;
}

/*
 *	Put an IDE/SCSI/SATA disk in standby mode.
 *	Code stolen from hdparm.c
 */
static int do_standby_disk(int fd)
{
#ifndef WIN_STANDBYNOW1
#define WIN_STANDBYNOW1 0xE0
#endif
#ifndef WIN_STANDBYNOW2
#define WIN_STANDBYNOW2 0x94
#endif
	unsigned char args1[4] = {WIN_STANDBYNOW1,0,0,0};
	unsigned char args2[4] = {WIN_STANDBYNOW2,0,0,0};

	if (fd < 0)
		return -1;

	if (ioctl(fd, HDIO_DRIVE_CMD, &args1) &&
	    ioctl(fd, HDIO_DRIVE_CMD, &args2))
		return -1;

	return 0;
}

/*
 *	Put all specified disks in standby mode.
 */
static int do_standby_disks(const int *fds, int count)
{
	int i;

	for (i = 0; i < count; i++)
		do_standby_disk(fds[i]);

	return 0;
}

/*
 *	First find all IDE/SCSI/SATA disks, then put them in standby mode.
 *	This has the side-effect of flushing the writecache,
 *	which is exactly what we want on poweroff.
 */
int hddown(void)
{
	const char *disks[MAX_DISKS];
	int fds[MAX_DISKS];
	int count = 0;
	int result1, result2;

	result1 = find_idedisks(disks, MAX_DISKS, &count);
	result2 = find_scsidisks(disks, MAX_DISKS, &count);

	open_disks(disks, fds, count);
	do_standby_disks(fds, count);

	return (result1 ? result1 : result2);
}

int hdflush(void)
{
	return 0;
}

#endif /* ! USE_SYSFS */
#else /* __linux__ */

int hddown(void)
{
	return 0;
}

int hdflush(void)
{
	return 0;
}

#endif /* __linux__ */

#ifdef STANDALONE
int main(int argc, char **argv)
{
	return (hddown() == 0);
}
#endif

