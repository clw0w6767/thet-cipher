# THET v21 - 实验性对称加密算法

**不可用于生产环境。未经过任何审计。**

这是一个学习项目。我把它发出来是为了获得密码学社区的反馈。
请勿用它保护真实数据。

真实场景请使用 XChaCha20-Poly1305 或 AES-256-GCM。

---

## 这是什么？

THET v21 是我为了理解密码学如何真正工作而自设计的对称加密算法。
它经历了约 15 个版本（v7 -> v21），每一版都修掉了迭代审查发现的 bug。

最终设计刻意选择无聊：

- 三流 XOR 密钥流：HMAC-SHA256 XOR HMAC-SHA3-256 XOR BLAKE2b
- HKDF-SHA512 做密钥分离（7 把独立子密钥）
- 双 MAC：HMAC-SHA512 + BLAKE2b-MAC（两个独立原语家族）
- scrypt（N=2^17, r=8, p=1）做口令派生
- 随机 16 字节 nonce（不是 SIV；不存在 nonce 重用问题）
- 流式，两遍解密，原子 rename
- Rust 实现，加固 I/O

## 它为什么存在？

它不该存在。这是一个学习产物。真实加密应该用经过审计的标准。
如果你正在读它来评估要不要用它：别用。

## 安全设计

完整规范见 SPEC.md。

三流密钥流：

    s1 = HMAC-SHA256(k_enc1, LBL_ENC1 || n1 || block_ctr)
    s2 = HMAC-SHA3-256(k_enc2, LBL_ENC2 || n2 || block_ctr)
    s3 = BLAKE2b(k_enc3, LBL_ENC3 || n3 || block_ctr)
    keystream_block = s1 XOR s2 XOR s3

安全性归约到：HMAC-SHA256、HMAC-SHA3-256、BLAKE2b 至少一个是 PRF。

双 MAC：

    mac1 = HMAC-SHA512(k_mac1, ad || ciphertext)
    mac2 = BLAKE2b-MAC(k_mac2, ad || ciphertext)

安全性归约到：HMAC-SHA512、BLAKE2b-MAC 至少一个是安全 MAC。

## 构建

    cargo build --release

需要 Rust 1.70+。仅支持 Linux。

## 用法

    THET_PASSPHRASE="你的口令" ./target/release/thet21 encrypt 秘密.txt 秘密.thet21
    THET_PASSPHRASE="你的口令" ./target/release/thet21 decrypt 秘密.thet21 还原.txt

## 文件格式

    offset 0        : salt(16)      - scrypt 盐，每次加密随机
    offset 16       : nonce(16)     - 密钥流 nonce，每次加密随机
    offset 32       : ciphertext(N) - 明文 XOR 密钥流
    offset 32+N     : mac1(64)      - HMAC-SHA512
    offset 96+N     : mac2(64)      - BLAKE2b-MAC

## 已知限制

完整列表见 SECURITY.md。

- 无抗量子安全
- 无侧信道抵抗
- NFS 上 flock 不可靠
- 不防内核级攻击者
- 未经过任何人审计

## 版本历史

| 版本 | 关键变化 |
|------|----------|
| v7      | 初始版（有 bug） |
| v8-v12  | 迭代修复 |
| v13-v14 | AD 编码、SIV、域分离 |
| v15-v16 | SIV nonce 验证、规范文档 |
| v17-v18 | 去掉临时文件明文落盘，去掉冗余 SIV |
| v19-v20 | TOCTOU 防御、fstat 指纹、flock |
| v21     | Rust 重写，加固 I/O |

## 许可证

MIT。见 LICENSE。
