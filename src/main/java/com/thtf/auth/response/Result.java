package com.thtf.auth.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * ========================
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/7/24 9:44
 * Version: v1.0
 * ========================
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Result<T> {
    private int code;
    private String msg;
    private T data;

    public Result(int code, String msg) {
        this.code = code;
        this.msg = msg;
    }
}
