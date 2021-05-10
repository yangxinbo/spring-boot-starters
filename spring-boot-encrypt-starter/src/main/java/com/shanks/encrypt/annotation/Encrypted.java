package com.shanks.encrypt.annotation;

import java.lang.annotation.*;

/**
 * FileName    : 是否加密注解
 * Description :
 * 1、可以修饰类和方法，方法优先级大于类
 *
 * @author : Shanks
 * @version : 1.0
 * Create Date : 2020/10/12 15:27
 **/
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Encrypted {

    /**
     * 入参是否解密，默认解密
     */
    boolean isDecode() default true;

    /**
     * 出参是否加密，默认加密
     */
    boolean isEncode() default true;
}
