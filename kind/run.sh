#!/bin/bash

cd $(dirname $0)

kind delete cluster
set -eux

# Build Docker images
echo "Building Docker images..."
docker build -f Dockerfile.proxy -t ndfuse-proxy ../.
docker build -f Dockerfile.shim -t ndfuse-shim ../.

echo 0 | sudo tee /proc/sys/vm/mmap_min_addr
kind create cluster

# Load images into kind cluster
echo "Loading images into kind cluster..."
kind load docker-image ndfuse-proxy:latest
kind load docker-image ndfuse-shim:latest

# Deploy the pod
echo "Deploying ndfuse pod..."
kubectl apply -f pod.yaml

# Wait for the pod to be ready
echo "Waiting for pod to be ready..."
kubectl wait --for=condition=Ready pod/ndfuse-pod --timeout=60s

# Show pod status
echo "Pod status:"
kubectl get pod ndfuse-pod

kubectl exec -it ndfuse-pod -c ndfuse-shim -- /bin/bash -c "LIBZPHOOK=./libndfuseshim.so LD_PRELOAD=./libzpoline.so ls -l /mnt"
