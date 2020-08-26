#!/bin/bash

for h in shm.h if.h virtio_ring.h; do
	echo cp include/kernel/$h include/lkl/linux/
	cp include/kernel/$h include/lkl/linux/
done

