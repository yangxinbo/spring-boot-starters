package com.shanks.encrypt.config;

import lombok.Data;

/**
 * FileName    : 公钥私钥配置
 * Description :
 *
 * @author : Shanks
 * @version : 1.0
 * Create Date : 2020/11/17 11:16
 **/
@Data
public class SecureKey {

    private String privateKey;

    private String publicKey;

}
