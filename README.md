# go-encrypt

#### 初衷实现非对称加密联系

> 场景原理模拟,有A,B两人,A需要将一段消息发送给B且保证信息不泄漏,A使用B的公钥将信息加密,传递到B后使用B的私钥进行解密

- 加密

- 解密

> 场景原理模拟,有A,B两人,A需要对一段消息进行签名后发送给B,B确认信息是A发送的而没有被篡改,A对信息进行哈希然后用自己的私钥进行签名,之后将信息传递给B,B用A的公钥进行验签

- 签名

- 验签