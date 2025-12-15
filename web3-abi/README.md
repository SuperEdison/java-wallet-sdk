# web3-abi

智能合约 ABI 编解码（预留占位）。

## 状态

🚧 **开发中**

## 计划支持

| 功能 | 说明 | 状态 |
|------|------|------|
| 函数编码 | `transfer(address,uint256)` → calldata | 🚧 |
| 参数解码 | calldata → 参数值 | 🚧 |
| 事件解码 | 日志 → 事件数据 | 🚧 |
| ABI 解析 | JSON ABI → 类型安全调用 | 🚧 |

## 计划 API

```java
// 编码函数调用
byte[] calldata = AbiEncoder.encodeFunction(
    "transfer(address,uint256)",
    "0x742d35Cc...",
    BigInteger.valueOf(1000)
);

// 解码返回值
BigInteger balance = AbiDecoder.decode("uint256", returnData);
```
