package com.shanks.encrypt.advice;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.RandomUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.symmetric.AES;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.shanks.encrypt.annotation.Encrypted;
import com.shanks.encrypt.config.EncryptedConfig;
import com.shanks.encrypt.config.SecureKey;
import com.shanks.encrypt.constant.EncryptConstants;
import com.shanks.encrypt.exception.EncryptException;
import com.shanks.encrypt.res.HttpEncryptRes;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

/**
 * FileName    : 响应加密处理
 * Description : http加签
 * 响应参数结构
 * {"code":"200","msg":"ok","key":"123","data":"yyyyyyyy","timestamp":xxxxxx,"sign":"zzzzzzz"}
 *
 * @author : Shanks
 * @version : 1.0
 * Create Date : 2020/7/25 18:39
 **/
@Slf4j
@ControllerAdvice
public class EncryptResponseBodyAdvice implements ResponseBodyAdvice {

    private final ObjectMapper objectMapper;

    private EncryptedConfig encryptedConfig;

    public EncryptResponseBodyAdvice(ObjectMapper objectMapper, EncryptedConfig encryptedConfig) {
        this.objectMapper = objectMapper;
        this.encryptedConfig = encryptedConfig;
    }

    /**
     * 判断是否加密
     *
     * @param methodParameter
     * @param clazz
     * @return
     */
    @Override
    public boolean supports(MethodParameter methodParameter, Class clazz) {
        boolean isEncode = isEncode(methodParameter);
        if (EncryptConstants.STATUS_YES.equals(encryptedConfig.getShowLog())) {
            log.info("[响应加密] isEncode:{}", isEncode);
        }
        return isEncode;
    }

    /**
     * 生成签名和加密
     * <p>
     * step1 解析数据
     * step2 加密数据
     * step3 生成签名
     *
     * @param methodParameter
     * @param clazz
     * @return
     */
    @Override
    public Object beforeBodyWrite(Object object, MethodParameter methodParameter,
                                  MediaType mediaType, Class clazz,
                                  ServerHttpRequest serverHttpRequest,
                                  ServerHttpResponse serverHttpResponse) {
        try {
            HttpHeaders httpReqHeaders = serverHttpRequest.getHeaders();
            // step 1 解析数据
            String bodyStr = objectMapper.writeValueAsString(object);
            if (log.isDebugEnabled()) {
                log.debug("[响应加密] EncryptBodyStr:{}", bodyStr);
            }
            // 显示数据
            if (EncryptConstants.STATUS_YES.equals(encryptedConfig.getShowLog())) {
                log.info("[响应加密] bodyStr:{}", bodyStr);
            }

            //step2 加密数据
            String appId = httpReqHeaders.getFirst(EncryptConstants.HEAD_APP_ID);
            SecureKey secureKey = encryptedConfig.getClientKeyMap().get(appId);
            String publicKey = null;
            if (secureKey == null || StringUtils.isBlank((publicKey = secureKey.getPublicKey()))) {
                log.error("[响应加密] 未配置对应公钥或者证书 appId:{}", appId);
                throw new EncryptException(EncryptConstants.FAIL_PARAM_INVALID, EncryptConstants.FAIL_PARAM_INVALID_MSG);
            }
            long timestamp = System.currentTimeMillis();
            String aesKey = RandomUtil.randomString(32);
            String key = Base64.encodeUrlSafe(new RSA(null, publicKey).encrypt(aesKey, KeyType.PublicKey));
            AES aes = SecureUtil.aes(aesKey.getBytes());

            //step3 生成签名
            String nonce = RandomUtil.randomString(6);
            String data = Base64.encodeUrlSafe(aes.encrypt(bodyStr));
            String sign = SecureUtil.sha256(StringUtils.join(key, data, nonce, timestamp));

            HttpEncryptRes res = new HttpEncryptRes();
            res.setKey(key);
            res.setData(data);
            res.setTimestamp(timestamp);
            res.setNonce(nonce);
            res.setSign(sign);

            //组织响应数据
            HttpHeaders httpRespHeaders = serverHttpResponse.getHeaders();
            httpRespHeaders.set(EncryptConstants.HEAD_KEY, key);
            httpRespHeaders.set(EncryptConstants.HEAD_TIMESTAMP, String.valueOf(timestamp));
            httpRespHeaders.set(EncryptConstants.HEAD_NONCE, nonce);
            httpRespHeaders.set(EncryptConstants.HEAD_SIGN, sign);
            return data;
        } catch (JsonProcessingException ex) {
            log.error("[响应加密] 异常ex:{}", ex);
            throw new EncryptException(EncryptConstants.FAIL_ENCRYPT, EncryptConstants.FAIL_ENCRYPT_MSG);
        }
    }

    /**
     * 判断是否解密
     *
     * @param methodParameter
     * @return
     */
    private boolean isEncode(MethodParameter methodParameter) {

        Boolean open = EncryptConstants.STATUS_YES.equals(encryptedConfig.getOpen());
        if (!open) {
            return false;
        }

        //判断方法是否存在注解
        Encrypted methodAnnotation = methodParameter.getMethodAnnotation(Encrypted.class);
        if (methodAnnotation != null) {
            return methodAnnotation.isEncode();
        }

        //判断class是否存在注解
        Encrypted classAnnotation = methodParameter.getContainingClass().getAnnotation(Encrypted.class);
        if (classAnnotation != null) {
            return classAnnotation.isEncode();
        }
        return false;
    }
}
