# soulengine-decompiler
Decompiler for all programs based on the [SoulEngine](https://github.com/dim-s/soulengine). Although, it would be more accurate to call him a "source code stealer"  

### How it works
After injection, the zend *compile_string* function is hooked, which is necessary for any eval construct in PHP, and in soulengine any event or action uses the eval construct.  
In theory, any application that uses php in this way can have its source code stolen.  

### Hook library
Used library: [MinHook](https://github.com/TsudaKageyu/minhook)  
It doesn't matter which library is used, any library can be used

### Recommended injector
Any dll injector will work. But for it to work correctly, you need to suspend the process before injection, because all the code is recognized at runtime.  
Personally, I recommend my [process-injector](https://github.com/redeflesq/suspend-process-injector)
