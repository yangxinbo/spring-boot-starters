package com.shanks.encrypt.req;

import lombok.Data;

import java.io.Serializable;

/**
 * FileName    : HttpEncryptReq
 * Description :
 *
 * @author : Shanks
 * @version : 1.0
 * Create Date : 2020/7/27 14:10
 **/
@Data
public class HttpEncryptReq implements Serializable {
    /**
     * 秘钥
     */
    private String key;
    /**
     * 加密数据
     */
    private String data;
    /**
     * 时间戳，是客户端调用接口时对应的当前时间戳，时间戳用于防止DoS攻击。
     */
    private String timestamp;
    /**
     * 随机值，是客户端随机生成的值6位长度
     */
    private String nonce;
    /**
     * 用于参数签名，防止参数被非法篡改
     */
    private String sign;

}
