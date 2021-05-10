package com.shanks.encrypt.res;

import lombok.Data;

import java.io.Serializable;

/**
 * FileName    : HttpEncryptRes
 * Description :
 *
 * @author : Shanks
 * @version : 1.0
 * Create Date : 2020/7/27 14:10
 **/
@Data
public class HttpEncryptRes implements Serializable {

    private String key;
    /**
     * 数据
     */
    private String data;

    /**
     * 随机值，是客户端随机生成的值6位长度
     */
    private String nonce;

    /**
     * 时间戳
     */
    private Long timestamp;

    /**
     * 签名
     */
    private String sign;

}
