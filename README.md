# accumulator demo展示

此仓库fork自 https://github.com/hyperledger/indy-crypto ， 在原仓库的基础上，提取出CKS聚合器的实现、优化了接口、完成一个完整的演示流程

## 如何使用

执行demo所属单元测试（使用nocapture特性打开输出）
```bash
# cargo clean
# cargo test demo_accumulator -- --nocapture
```

## 演示流程

1. issuer生成撤销公钥、撤销私钥
2. issuer新建一个聚合器，输出聚合器公钥、聚合器私钥、聚合值
3. issuer将撤销公钥、聚合器公钥、聚合值公开
4. prover 1盲化自己的私钥
5. prover 1将自己的DID、盲化值发送给issuer
6. issuer为该用户分配一个之前未使用的撤销ID
7. issuer利用撤销ID和DID计算该用户的唯一身份标识$m_2$
8. issuer颁发未撤销证书，并将其发送给prover 1
9. prover 1验证未撤销证书的正确性
10. prover 1对未撤销证书进行偏移，并将偏移之后的未撤销证书存储下来
11. prover 1对未撤销证书进行盲化，并将盲化后的未撤销证书发送给verifier
12. verifier利用撤销公钥、聚合器公钥、聚合器值、盲化后的未撤销证书等进行验证（验证结果为true，表示prover 1在聚合器中）
13. issuer为prover 2颁发为撤销证书（过程和4-10相同）
14. prover 1根据新的聚合值、撤销公钥等内容更新自己的未撤销证据
15. prover 1和prover 2分别向verifier发送验证请求（过程和11-12相同）
16. verifier分别对prover 1和prover 2提交的未撤销证书进行验证（验证结果为true）
17. issuer撤销prover1
18. prover 1向verifier发送验证请求（过程和11-12相同）
19. verifier对prover 1进行验证（验证结果为false，表示prover 1已经不在聚合器中了）
20. prover 2根据新的聚合值、撤销公钥等内容更新自己的未撤销证据
21. prover 2向verifier发送验证请求（过程和11-12相同）
22. verifier对prover 2进行验证（验证结果为true，表示prover 2仍然在聚合器中）

## API

### Issuer

函数名：new_revocation_keys
* 功能：生成一对新的撤销公私钥
* 输入：无
* 输出：撤销公钥、撤销私钥

函数名：new_accumulator
* 功能：生成一个新的聚合器
* 输入：撤销公钥、聚合器中最多的元素个数
* 输出：聚合器公开内容（包括公钥和聚合值）、聚合器私钥


函数名：gen_credential_context
* 功能：计算一个prover的唯一标识
* 输入：prover的DID、撤销ID
* 输出：该prover的唯一标识

函数名：delete_from_accumulaor
* 功能：将一个元素从聚合器中删除
* 输入：撤销ID、聚合器的最多元素个数、聚合器公开内容、聚合器相关数据（封装为数据结构RevocationTailsAccessor）
* 输出：聚合器改变的内容（封装为数据结构RevocationRegistryDelta）

函数名：add_to_accumulaor
* 功能：将一个元素加入到聚合器中
* 输入：撤销ID、该用户的唯一标识、聚合器的最多元素个数、盲化后的prover私钥、聚合器公开内容、聚合器私钥、撤销公钥、撤销私钥、聚合器相关数据（封装为数据结构RevocationTailsAccessor）
* 输出：聚合器改变的内容（封装为数据结构RevocationRegistryDelta）

### Porver

函数名：generate_blinded_revocation
* 功能：盲化自己的私钥
* 输入：issuer的撤销公钥
* 输出：盲化后的prover私钥


函数名：check_revocation_credential
* 功能：检查issuer发回的未撤销证书是否正确
* 输入：未撤销证书、自己的私钥、撤销公钥、聚合器公开内容、未撤销证据
* 输出：true 如果未撤销证书是正确的；false如果未撤销证书是错误的


函数名：store_non_revocation_credential
* 功能：对未撤销证书进行偏移并保存
* 输入：未撤销证书、自己的私钥
* 输出：偏移之后的未撤销证书

函数名：init_non_revocation_proof
* 功能：盲化自己的未撤销证书
* 输入：未撤销证书、聚合器公开内容、撤销公钥、证据
* 输出：盲化之后的未撤销证据

函数名：finalize_non_revocation_proof
* 功能：对init_non_revocation_proof的输出再次盲化
* 输入：盲化之后的未撤销证据、挑战challenge
* 输出：最终的未撤销证据（盲化之后的）


### Verifier

函数名：verify
* 功能：对prover提交的未撤销证据进行验证
* 输入：挑战challenge、撤销公钥、聚合器公开值、盲化之后的未撤销证据、随机数
* 输出：true如果验证通过、false如果验证不通过


## 动态库冲突问题解决方案

删除编译好的同名依赖库（上周rust更新会出现一个warning，多次编译如果覆盖已存在的重名库会告警）

```bash
rm  /Users/asher/Desktop/helloworld/target/debug/deps/libindy_crypto.dylib
```

