package com.thtf.auth.model;

import lombok.Data;

import java.io.Serializable;

/**
 * ========================
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/7/25 10:25
 * Version: v1.0
 * ========================
 */
@Data
public class SysPermission implements Serializable{
    private static final long serialVersionUID = 7510552869226022669L;

    private int id;

    private String alias;

    private String name;

    private int pid;
}
