package com.shanks.encrypt.exception;

import lombok.Getter;
import lombok.Setter;

/**
 * FileName    : EncryptException
 * Description :
 *
 * @author : Shanks
 * @version : 1.0
 * Create Date : 2020-7-13 20:15:06
 **/
@Getter
@Setter
public class EncryptException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private int code;

    public EncryptException(int code, String message) {
        super(message);
        this.code = code;
    }
}
