Build instructions
------------------

Build the release kernel from the repository root.

```sh
cargo run -p xtask -- build --platform x86_64-uefi --release
```

Use `aarch64-uefi` to build for AArch64. 

License
-------
Original project code uses the Apache License, Version 2.0. See `LICENSE`.
Third-party code keeps its own terms. See `NOTICE` and the license files in
`third_party`.
