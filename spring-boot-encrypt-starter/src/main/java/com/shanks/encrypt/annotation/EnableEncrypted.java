package com.shanks.encrypt.annotation;

import com.shanks.encrypt.advice.EncryptRequestBodyAdvice;
import com.shanks.encrypt.advice.EncryptResponseBodyAdvice;
import com.shanks.encrypt.config.EncryptedConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

/**
 * FileName    : 启用加解密
 * Description :
 *
 * @author : Shanks
 * @version : 1.0
 * Create Date : 2020/10/12 15:27
 **/
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@Import({
        EncryptedConfig.class,
        EncryptRequestBodyAdvice.class,
        EncryptResponseBodyAdvice.class
})
public @interface EnableEncrypted {

}
