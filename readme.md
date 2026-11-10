Build instructions
------------------

Build the release kernel from the repository root.

```sh
cargo run -p xtask -- build --platform x86_64-uefi --release
```

Use `aarch64-uefi` to build for AArch64. Both kernel targets use full link-time optimization across Rust and mimalloc.

Parallel heap benchmark
-----------------------

On x64 Windows, run this command from the repository root. It uses Python, Clang, the Windows SDK, and the QEMU WHPX launch.

```powershell
python tooling/heap-bench/compare.py --cpus 1,2,4
```

Each worker allocates blocks in batches of 128, writes one byte to each block, and frees them in a different order. One pair is one allocation and one free on the same worker. Each timed sample contains 33,554,432 pairs per worker. The two cases use 64-byte blocks and mixed sizes from 16 to 4096 bytes. Workers warm their heaps before timing starts.

The comparison uses the median of seven samples per run, then the median across three kernel boots and three native Windows processes. The report also gives the physical heap bytes at mimalloc startup and before the workers start. Results go to `target/heap-bench/run/comparison.json`. The command returns 1 if any case is below 90% of Windows throughput. Set `RUSTOS_DISK` to use a different system disk image.

The GitHub `Kernel benchmarks` workflow runs `heap.mimalloc` at 1, 2, and 4 vCPUs. It uses ten boots per CPU count and compares allocation/free pairs per second against the trusted kernel baseline with an 8% tolerance.

License
-------
Original project code uses the Apache License, Version 2.0. See `LICENSE`.
Third-party code keeps its own terms. See `NOTICE` and the license files in
`third_party`.
