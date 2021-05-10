package com.shanks.encrypt.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

/**
 * FileName    : EncryptedConfig
 * Description :
 *
 * @author : Shanks
 * @version : 1.0
 * Create Date : 2020/7/28 0:01
 **/
@Data
@Configuration
@ConfigurationProperties(prefix = "app.encrypt")
public class EncryptedConfig {

    /**
     * 客户端秘钥（公钥）
     */
    private Map<String, SecureKey> clientKeyMap = new HashMap<>();

    /**
     * 服务器秘钥（私钥）
     */
    private Map<String, SecureKey> serverKeyMap = new HashMap<>();

    /**
     * 是否开启
     */
    private int open = 1;

    /**
     * 是否显示日志
     */
    private int showLog = 0;

}
