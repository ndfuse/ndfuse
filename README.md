# ndfuse

Mount FUSE-based filesystem without `/dev/fuse`

## Limitation

- Cannot execute binary via ndfuse because binaries are directly executed via execv(2) syscalls.

## NOTICE

ndfuse utilizes [zpoline](https://github.com/yasukata/zpoline) to hook user program's syscalls.

Before starting to use, you need to configure `/proc/sys/vm/mmap_min_addr` to be `0`.
```
echo 0 | sudo tee /proc/sys/vm/mmap_min_addr
```

Also, ndfuse uses socketpair to relay messages between user's fuse program and ndfuse-proxy.
ndfuse-proxy configures 'max_read' according to the socket's buffer size.
To get better performance, you should configure socket buffer size larger.
```
sudo sysctl -w net.core.wmem_max=16777216
sudo sysctl -w net.core.rmem_max=16777216
```
