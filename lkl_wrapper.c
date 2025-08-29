#include <lkl.h>
#include <lkl_host.h>

int lkl_wrapper_init(void) {
    return lkl_init(&lkl_host_ops);
}

int lkl_wrapper_start_kernel(const char *cmd_line) {
    return lkl_start_kernel(cmd_line);
}

void lkl_wrapper_cleanup(void) {
    lkl_cleanup();
}

long lkl_wrapper_sys_mknod(const char *pathname, int mode, int dev) {
    return lkl_sys_mknod(pathname, mode, dev);
}

long lkl_wrapper_sys_open(const char *pathname, int flags, int mode) {
    return lkl_sys_open(pathname, flags, mode);
}

long lkl_wrapper_sys_close(int fd) {
    return lkl_sys_close(fd);
}

long lkl_wrapper_sys_mkdir(const char *pathname, int mode) {
    return lkl_sys_mkdir(pathname, mode);
}

long lkl_wrapper_sys_mount(char *source, char *target, 
                           char *filesystemtype, unsigned long mountflags, 
                           void *data) {
    return lkl_sys_mount(source, target, filesystemtype, mountflags, data);
}

long lkl_wrapper_sys_read(int fd, void *buf, size_t count) {
    return lkl_sys_read(fd, buf, count);
}

long lkl_wrapper_sys_write(int fd, const void *buf, size_t count) {
    return lkl_sys_write(fd, buf, count);
}

void* lkl_wrapper_sys_mmap(void *addr, size_t length, int prot, int flags, 
                           int fd, off_t offset) {
    return lkl_sys_mmap(addr, length, prot, flags, fd, offset);
}

long lkl_wrapper_sys_statx(int dirfd, const char *pathname, unsigned flags, unsigned mask, struct statx *statxbuf) {
    return lkl_sys_statx(dirfd, pathname, flags, mask, (struct lkl_statx*)statxbuf);
}

long lkl_wrapper_sys_fstat(int fd, struct lkl_stat *statbuf) {
    return lkl_sys_fstat(fd, statbuf);
}

long lkl_wrapper_sys_getdents64(int fd, struct dirent64 *dirent, unsigned int count) {
    return lkl_sys_getdents64(fd, (struct lkl_linux_dirent64 *)dirent, count);
}

const char* lkl_wrapper_strerror(int err) {
    return lkl_strerror(err);
}
