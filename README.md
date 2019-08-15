# accumulator demo展示

删除编译好的同名依赖库（上周rust更新会出现一个warning，多次编译如果覆盖已存在的重名库会告警）

rm  /Users/asher/Desktop/helloworld/target/debug/deps/libindy_crypto.dylib

执行demo所属ut

cargo test demo_accumulator -- --nocapture

使用nocapture特性打开输出
