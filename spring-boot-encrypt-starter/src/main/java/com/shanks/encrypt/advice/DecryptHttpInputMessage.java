package com.shanks.encrypt.advice;

import cn.hutool.core.codec.Base64;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.symmetric.AES;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.shanks.encrypt.config.EncryptedConfig;
import com.shanks.encrypt.config.SecureKey;
import com.shanks.encrypt.constant.EncryptConstants;
import com.shanks.encrypt.exception.EncryptException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;

/**
 * FileName    : DecryptHttpInputMessage
 * Description :
 *
 * @author : Shanks
 * @version : 1.0
 * Create Date : 2020/7/27 14:05
 **/
@Slf4j
public class DecryptHttpInputMessage implements HttpInputMessage {

    private HttpHeaders headers;
    private InputStream body;

    public DecryptHttpInputMessage(HttpInputMessage httpInputMessage, MethodParameter parameter, Type targetType,
                                   Class<? extends HttpMessageConverter<?>> converterType,
                                   ObjectMapper objectMapper, EncryptedConfig encryptedConfig) {
        try {
            // 获取参数
            HttpHeaders httpHeaders = httpInputMessage.getHeaders();
            String appId = httpHeaders.getFirst(EncryptConstants.HEAD_APP_ID);
            String productId = httpHeaders.getFirst(EncryptConstants.HEAD_PRODUCT_ID);
            String key = httpHeaders.getFirst(EncryptConstants.HEAD_KEY);
            String timestamp = httpHeaders.getFirst(EncryptConstants.HEAD_TIMESTAMP);
            String nonce = httpHeaders.getFirst(EncryptConstants.HEAD_NONCE);
            String sign = httpHeaders.getFirst(EncryptConstants.HEAD_SIGN);
            String debugEnabled = httpHeaders.getFirst(EncryptConstants.HEAD_DEBUG_ENABLED);

            // 获取服务器私钥
            SecureKey secureKey = encryptedConfig.getServerKeyMap().get(productId);
            String privateKey = null;
            if (secureKey == null || StringUtils.isBlank((privateKey = secureKey.getPrivateKey()))) {
                log.error("[请求解密] 未配置对应私钥或者证书 productId:{}", productId);
                throw new EncryptException(EncryptConstants.FAIL_PARAM_INVALID, EncryptConstants.FAIL_PARAM_INVALID_MSG);
            }
            String data = IOUtils.toString(httpInputMessage.getBody(), "UTF-8");
            if (EncryptConstants.STATUS_YES.equals(encryptedConfig.getShowLog()) || EncryptConstants.STATUS_YES.equals(debugEnabled)) {
                log.info("appId:{}", appId);
                log.info("productId:{}", productId);
                log.info("key:{}", key);
                log.info("timestamp:{}", timestamp);
                log.info("nonce:{}", nonce);
                log.info("sign:{}", sign);
                log.info("data:{}", data);
            }

            // 验签
            String signatureStr = StringUtils.join(key, data, nonce, timestamp);
            String checkSign = SecureUtil.sha256(signatureStr);
            if (!checkSign.equals(sign)) {
                log.warn("[请求解密] 无效签名 sign:{} checkSign:{} signSb:{}", sign, checkSign, signatureStr);
                throw new EncryptException(EncryptConstants.FAIL_SIGN, EncryptConstants.FAIL_SIGN_MSG);
            }

            // 解密
            RSA rsa = new RSA(privateKey, null);
            // step1 RSA私钥解密AES秘钥
            String aesKey = new String(rsa.decrypt(Base64.decode(key), KeyType.PrivateKey));
            // ste1 AES解密数据
            AES aes = SecureUtil.aes(aesKey.getBytes());
            String decodeData = aes.decryptStr(data);
            // 赋值
            this.headers = httpInputMessage.getHeaders();
            this.body = IOUtils.toInputStream(decodeData, "UTF-8");
        } catch (IOException ex) {
            log.error("[请求解密] 异常ex:{}", ex);
            throw new EncryptException(EncryptConstants.FAIL_DECODE, EncryptConstants.FAIL_DECODE_MSG);
        }
    }

    @Override
    public HttpHeaders getHeaders() {
        return headers;
    }

    @Override
    public InputStream getBody() {
        return body;
    }


}
