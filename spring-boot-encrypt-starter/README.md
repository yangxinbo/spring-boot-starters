

# 简介

该项目主要解决Content-Type:application/json对http请求响应进行加密。

基于SpringBoot2开发,依赖hutool-crypto加密,使用Aes进行加密数据，使用Res加密Aes秘钥

#### 使用说明

##### 一准备工作
- 将项目deploy私服或者install到本地(jar包未上传到中央仓库)

- Maven Dependency
```
    <groupId>com.shanks</groupId>
    <artifactId>spring-boot-encrypt-starter</artifactId>
    <version>1.0.0-SNAPSHOT</version>
```
- @EnableEncrypted
 启动类上的@EnableEncrypted注解是用来开启功能的,通过@Import导入自动配置类

 - @Encrypted
 使用注解修饰controller，可修饰方法和类，优先级方法>类  
 isDecode 默认true,请求是否解密，默认解密   
 isEncode 默认true,响应是否加密，默认加密   

- 配置文件
```
服务器配置
app.encrypt.serverKeyMap[productId].privateKey=服务器私钥
app.encrypt.clientKeyMap[appId].publicKey=客户端公钥
```
生产秘钥方法  
可以参考com.shanks.encrypt.EncryptTest
```
    @Test
    public void genRsaKey() {
        RSA rsa = SecureUtil.rsa();
        String priStr = Base64.encodeUrlSafe(rsa.getPrivateKey().getEncoded());
        String pubStr = Base64.encodeUrlSafe(rsa.getPublicKey().getEncoded());
        log.info("公钥 :{}", pubStr);
        log.info("私钥 :{}", priStr);
    }
```

##### 二请求响应参数说明

**请求**  
Header参数  
    appId：应用Id唯一  
    productId：产品Id（一个产品有多个应用）  
    key：rsa加密的aes秘钥  
    nonce：随机值，是客户端随机生成的值6位长度  
    timestamp：时间戳，是客户端调用接口时对应的当前时间戳，时间戳用于防止DoS攻击。  
    sign：用于参数签名，防止参数被非法篡改  
body  
    密文  
**响应**
    key：rsa加密的aes秘钥  
    nonce：随机值，是客户端随机生成的值6位长度    
    timestamp：时间戳  
    data：密文  
    sign：签名值

**案例**

```
 TODO 
```

​      

#### 工作原理
用的spirngMVC的中RequestBodyAdviceAdapter、ResponseBodyAdvice

