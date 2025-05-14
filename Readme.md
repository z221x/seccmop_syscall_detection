# seccmop_syscall_detection
> 由于seccomp-unotify的一些特性，这个syscall的检测也只能起到记录的作用，无法再做到更多更高级的操作。
## 编译
``` shell
cd client
madir build && cd build
make
cd serve
madir build && cd build
make
```
## 使用方法
选择一个的想要检测的app使用的lib库进行注入
``` shell
python ../tools/Liefinject.py app-debug.apk . libseccomp.so libdetection_serve.so arm64 -sign --keystore ../keystore/detection.jks --alias key0 --password 123456
```
然后运行
``` shell
./detection_client 
```