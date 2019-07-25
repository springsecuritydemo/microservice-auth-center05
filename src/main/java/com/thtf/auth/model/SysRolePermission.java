package com.thtf.auth.model;

import lombok.Data;

import java.io.Serializable;

/**
 * ========================
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/7/25 10:29
 * Version: v1.0
 * ========================
 */
@Data
public class SysRolePermission implements Serializable{

    private static final long serialVersionUID = 7081950007398765100L;
    private Integer roleId;

    private Integer permissionId;
}
