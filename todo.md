todo list because I have been forgetting stuff i need to complete

### AArch64
  1. [ ] Finish aarch64-vmsa crate.
  2. [ ] Finish aarch64 bootloader.
  3. [ ] Make debug.json platform independent, find a way for xtask to be able to pass info to it.
  4. [ ] Expand xtask for aarch64 boot. 
  5. [ ] Impl the platform traits for kernel_types, kernel_api, kernel_stub, and the kernel
  6. [ ] Test everything.

### Drivers
  1. [ ] Add a nvme driver.
  2. [ ] Add a usb driver.
  3. [ ] Create the mouse stack. 
  4. [ ] Change how the filesystem hint works so that preferably the pnp manager has no filesystem specific code.
  5. [ ] Expand the pci(e) protocol. 
  
### User I/O
  1. [ ] Currently the request_io code expects the user to provide a raw unpinned buffer. Change this to expect some type of registered buffer and so that read no longer allocates.
  2. [ ] Expose a way for users to register there buffers. 
  3. [ ] properly handle invalid user ptrs.

### Paging 
  1. [ ] Pinned pages for iobuffers and stuff
  2. [ ] subsytem for providing zeroed frames; i like how windows does this. 

### Kernel General 
  1. [ ] Move stack unwinding out of the kernel to its own crate 
  2. [ ] Symbolic stack unwinds
  3. [ ] Clearer stack unwind api, I like what the std lib does with Backtrace 
  4. [ ] Change the registry from inline proto to a .proto file
