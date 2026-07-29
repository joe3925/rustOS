todo list because I have been forgetting stuff I need to complete

If there is a * it must be completed before user space is started 

# Kernel
## AArch64 (AA64)
1. [ ] * Finish aarch64-vmsa crate.
2. [ ] * Finish aarch64 bootloader.
3. [ ] * Make debug.json platform independent, find a way for xtask to be able to pass info to it.
4. [ ] * Expand xtask for aarch64 boot. 
5. [ ] * Impl the platform traits for kernel_types, kernel_api, kernel_stub, and the kernel
6. [ ] * Test everything.

## Drivers (DRI) - Complete last
1. [ ] Add a nvme driver.
2. [ ] Add a usb driver.
3. [ ] * Create the mouse stack. 
4. [x] Change how the filesystem hint works so that preferably the pnp manager has no filesystem specific code.
5. [ ] Expand the pci(e) protocol. 

## User I/O (UIO)
1. [x] * Currently the request_io code expects the user to provide a raw unpinned buffer. Change this to expect some type of registered buffer and so that read no longer allocates.
2. [x] * Expose a way for users to register there buffers. 
3. [ ] * properly handle invalid user ptrs.

## Proc Management (PRM)
1. [ ] * Audit how the proc manager handles user space mappings I wrote that a while ago and haven't changed it much while the kernel has evolved a lot.
2. [ ] * Make sure that the way queues work is still in line with the direction I am taking the OS.  

## FrameBuffer/Window Management (FBM)
1. [ ] * Figure out how I will share the frame buffer with User Space.  

## Paging (PAG)
1. [x] * Pinned pages for iobuffers and stuff
2. [ ] subsytem for providing zeroed frames; i like how windows does this. 
3. [ ] Get rid of the global page table lock, fragment the lock on the page tables or create a lockless design (if possible). 

## Kernel General (KEG)
1. [x] Clearer stack unwind api, I like what the std lib does with Backtrace 
2. [x] * Change the registry from inline proto to a .proto file

## Executor (EXE)
1. [ ] Figure out emergency interrupt queue exhaustion.

## Error handling (ERH) (all around messy and I need to refactor it, not sure in what direction I want to take it yet)
1. [x] * Figure out how error handling should be refactored
2. [x] Stop using format_args its gonna be none pretty much all the time.  

## Benchmarking (BEN)
1. [ ] An all around mess needs to be cleaned up but im not sure how yet. 

### IoBuffers (IOB)
1. [x] Address the iobuffer back pointer causing performance loss. 
2. [ ] Add iobuffer overlap checking without hurting performance.


# User Space 
## User Space DLL (USD)
1. [ ] Figure out a name for it.
2. [ ] Figure out where it goes.
3. [ ] Figure out what its role and scope is. 
4. [ ] Plan the structure. 
5. [ ] Figure out if i will have the User Space DLL also have a small internal manager for the proc registered IoBuffers. 
## User Space Runtime (USR)
1. [ ] Figure out if I want an actual native runtime or maybe I can do something to support a RustOSRuntime crate or maybe neither.
## Window management (WIM)
1. [ ] Plan Window management
