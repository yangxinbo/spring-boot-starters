package com.shanks.encrypt;

import cn.hutool.core.codec.Base64;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.RSA;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

/**
 * FileName    : com.shanks.encrypt
 * Description :
 *
 * @author : Shanks
 * @version : 1.0
 * Create Date : 2021/4/28 20:29
 **/
@Slf4j
public class EncryptTest {

    /**
     * 生产Rsa秘钥对
     */
    @Test
    public void genRsaKey() {
        RSA rsa = SecureUtil.rsa();
        String priStr = Base64.encodeUrlSafe(rsa.getPrivateKey().getEncoded());
        String pubStr = Base64.encodeUrlSafe(rsa.getPublicKey().getEncoded());
        log.info("公钥 :{}", pubStr);
        log.info("私钥 :{}", priStr);
    }

}
