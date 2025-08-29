# ndfuse

Mount FUSE-based filesystem without `/dev/fuse`

## Limitation

- Cannot execute binary via ndfuse because binaries are directly executed via execv(2) syscalls.
