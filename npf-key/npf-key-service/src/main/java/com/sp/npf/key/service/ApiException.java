package com.sp.npf.key.service;

/** 帶 HTTP 狀態的業務例外。 */
public class ApiException extends RuntimeException {

    private final int status;

    public ApiException(int status, String message) {
        super(message);
        this.status = status;
    }

    public int getStatus() {
        return status;
    }
}
