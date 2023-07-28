# soulengine-decompiler
Decompiler for all programs based on SoulEngine  

### How it works
After the injection, the zend *compile_string* function is hooked, which is needed for any eval construction in PHP. Just in soulengine, any event or action uses the eval construction.

### Hook library
Used library: [MinHook](https://github.com/TsudaKageyu/minhook)  
It doesn't matter which library is used, any library can be used

### Recommended injector
Any dll injector will work. But for it to work correctly, you need to suspend the process before injection, because all the code is recognized at runtime.  
Personally, I recommend [SPInjector](https://github.com/redeflesq/SPInjector)
