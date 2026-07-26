
# USD-3
## Current Requirements  
- It must create a wrapper over all the raw syscalls.
- It must be callable from C or Rust code. 
- Don't get to fancy with the functions, it should be that is idiomatic and can be easily integrated into a std lib impl with minimal porting. 
- ( "(a)sync wrappers" ) Since all I/O syscalls are async the dll is responsible for exposing sync wrappers (open_file for example) that complete without the caller needing to think about async completion tokens, the kernels internal queue or anything like that, it should also of course expose the actual async interface so that things like reactors are still possible.
- ( "buffer wrappers" ) On top of the last point there should also be wrappers so that callers don't need to think about registering there buffers, like something that registers the buffer inline so that the user of the dll in a simple case where they don't care about the iobuffer can just pass a raw ptr and a len. 
## Open questions and notes on them 

### Sync/async and buffer wrapper API
**Question:** How do I get (a)sync wrappers and buffer wrappers while maintaining a minimal api? 

**Thoughts:** 
    
- I want to avoid function matrixes (example: (read_file_x_y) where x is if it needs a iobuffer and y is if it needs a completion token. this would mean the api would need to expose 4 different read files)

### Automatic IoBufferBacking management

**Question:** IobufferBacking creation is expensive and an IoBufferBacking must be created to create an IoBuffer. How much should the buffer handling abstract, should it internally create a global IoBufferBacking try to get a buffer from that and fallback to inline IoBufferBacking creation if it can't or is that over engineered and I should just create and drop them inline? 

**Thoughts:** 
- The user can always create there own IobufferBacking and call the io functions that let them pass there own iobuffer if they needs to call an io function in a hot path or performance matters.

- It becomes complicated to be able to create IoBuffers in parallel from the same backing.

- If the user is taking the naive approach and letting the DLL handle the IoBuffer they probably aren't running a bunch of concurrent I/O request.

- Considering how simple this is for me to impl, it greatly improves the best case performance and the worse case (The IoBufferBacking is exceeded because the user is running a bunch of IoOps at the same time), isn't hurt at all, this fast path could be worth it, I will probably end up needing to solve the IoBufferBacking parallelism problem if I impl this in the dll or not.

# FBM-GEN
