package com.shanks.encrypt.constant;

/**
 * FileName    : 常量
 * Description :
 *
 * @author : Shanks
 * @version : 1.0
 * Create Date : 2020-7-13 20:15:06
 **/
public interface EncryptConstants {

    /**
     * yes 1
     */
    Integer STATUS_YES = 1;

    /**
     * no 0
     */
    Integer STATUS_NO = 0;

    /**
     * 当前客户端版本名称
     */
    String HEAD_VER = "ver";

    /**
     * 当前客户端版本号
     */
    String HEAD_VCODE = "vcode";

    /**
     * 手机设备号
     */
    String HEAD_DID = "did";

    /**
     * 设备类型：1:android，2:iphone
     */
    String HEAD_DTYPE = "dtype";

    /**
     * 来源渠道ID
     */
    String HEAD_CHANNEL = "channel";
    /**
     * 产品ID
     */
    String HEAD_PRODUCT_ID = "productId";

    /**
     * 应用ID
     */
    String HEAD_APP_ID = "appId";

    /**
     * 秘钥
     */
    String HEAD_KEY = "key";
    /**
     * 随机值，是客户端随机生成的值6位长度
     */
    String HEAD_NONCE = "nonce";
    /**
     * 时间戳，是客户端调用接口时对应的当前时间戳，时间戳用于防止DoS攻击。
     */
    String HEAD_TIMESTAMP = "timestamp";
    /**
     * 用于参数签名，防止参数被非法篡改
     */
    String HEAD_SIGN = "sign";

    /**
     * 是否开启debug
     */
    String HEAD_DEBUG_ENABLED = "debugEnabled";

    /**
     * 用户登录head参数
     */
    String HEAD_TOKEN = "token";

    /**
     * 设备类型：1:android，2:iphone
     */
    Integer DEVICE_DEFAULT_TYPE = 1;
    Integer DEVICE_TYPE_ANDROID = 1;
    Integer DEVICE_TYPE_IOS = 2;

    /**
     * 成功标记
     */
    Integer SUCCESS = 200;
    String SUCCESS_MSG = "OK";

    /**
     * 失败标记
     */
    Integer FAIL = 500;
    String FAIL_MSG = "Server is busy, please try again later";

    /**
     * 参数异常 3000 ~ 3999（缺少参数、参数校验、业务校验）
     */
    Integer FAIL_PARAM = 3000;
    String FAIL_PARAM_MSG = "Parameter abnormal";

    /**
     * 参数为空
     */
    Integer FAIL_PARAM_NULL = 3001;
    String FAIL_PARAM_NULL_MSG = "Parameter is empty";

    /**
     * 参数无效
     */
    Integer FAIL_PARAM_INVALID = 4000;
    String FAIL_PARAM_INVALID_MSG = "Invalid argument";

    /**
     * 无效签名
     */
    Integer FAIL_SIGN = 4001;
    String FAIL_SIGN_MSG = "Invalid signature";

    /**
     * 解密无效，参数有误
     */
    Integer FAIL_DECODE = 4002;
    String FAIL_DECODE_MSG = "The encrypted response is abnormal, and the parameters are incorrect";

    /**
     * 加密响应异常
     */
    Integer FAIL_ENCRYPT = 4003;
    String FAIL_ENCRYPT_MSG = "The encrypted response is abnormal, and the parameters are incorrect";


}
