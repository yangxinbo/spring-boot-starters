package com.shanks.encrypt.advice;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.shanks.encrypt.annotation.Encrypted;
import com.shanks.encrypt.config.EncryptedConfig;
import com.shanks.encrypt.constant.EncryptConstants;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdviceAdapter;

import java.io.IOException;
import java.lang.reflect.Type;

/**
 * FileName    : 请求解密
 * Description :
 * http 请求验签解密
 * http 请求解密
 * 请求参数结构
 * {"timestamp":xxxxxx,"data":"yyyyyyyy","sign":"zzzzzzz"}
 *
 * @author : Shanks
 * @version : 1.0
 * Create Date : 2020/7/25 17:46
 **/
@Slf4j
@ControllerAdvice
public class EncryptRequestBodyAdvice extends RequestBodyAdviceAdapter {

    private EncryptedConfig encryptedConfig;

    private final ObjectMapper objectMapper;

    public EncryptRequestBodyAdvice(EncryptedConfig encryptedConfig, ObjectMapper objectMapper) {
        this.encryptedConfig = encryptedConfig;
        this.objectMapper = objectMapper;
    }

    /**
     * 判断是否验签解密
     *
     * @param methodParameter
     * @param type
     * @param clazz
     * @return true 验签解密 false 不验签解密
     */
    @Override
    public boolean supports(MethodParameter methodParameter, Type type, Class<? extends HttpMessageConverter<?>> clazz) {
        boolean isDecode = isDecode(methodParameter);
        if (EncryptConstants.STATUS_YES.equals(encryptedConfig.getShowLog())) {
            log.info("[请求解密] isDecode:{}", isDecode);
        }
        return isDecode;
    }


    /**
     * 验签解密
     *
     * @param inputMessage
     * @param methodParameter
     * @param targetType
     * @param converterType
     * @return
     * @throws IOException
     */
    @Override
    public HttpInputMessage beforeBodyRead(HttpInputMessage inputMessage, MethodParameter methodParameter, Type targetType,
                                           Class<? extends HttpMessageConverter<?>> converterType) throws IOException {
        boolean isDecode = isDecode(methodParameter);
        if (isDecode) {
            return new DecryptHttpInputMessage(inputMessage, methodParameter, targetType, converterType, objectMapper, encryptedConfig);
        } else {
            return super.beforeBodyRead(inputMessage, methodParameter, targetType, converterType);
        }
    }

    /**
     * 判断是否解密
     *
     * @param methodParameter
     * @return
     */
    private boolean isDecode(MethodParameter methodParameter) {

        // 判断是否加密开关
        Boolean open = EncryptConstants.STATUS_YES.equals(encryptedConfig.getOpen());
        if (!open) {
            return false;
        }

        //判断方法是否存在注解
        Encrypted methodAnnotation = methodParameter.getMethodAnnotation(Encrypted.class);
        if (methodAnnotation != null) {
            return methodAnnotation.isDecode();
        }

        //判断class是否存在注解
        Encrypted classAnnotation = methodParameter.getContainingClass().getAnnotation(Encrypted.class);
        if (classAnnotation != null) {
            return classAnnotation.isDecode();
        }
        return false;
    }

}
