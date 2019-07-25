package com.thtf.auth.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * ========================
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/7/25 10:59
 * Version: v1.0
 * ========================
 */
@RestController
@Slf4j
public class UserController {

    @GetMapping("/createUser")
    @PreAuthorize("hasAnyRole('ADMIN','USER_ALL','USER_CREATE')")
    public String add() {
        return "具有【用户添加】权限";
    }

    @GetMapping("/updateUser")
    @PreAuthorize("hasAnyRole('ADMIN','USER_ALL','USER_EDIT')")
    public String update() {
        return "具有【用户修改】权限";
    }

    @GetMapping("/delUser")
    @PreAuthorize("hasAnyRole('ADMIN','USER_ALL','USER_DELETE')")
    public String delete() {
        return "具有【用户删除】权限";
    }

    @GetMapping("/users")
    @PreAuthorize("hasAnyRole('ADMIN','USER_ALL','USER_SELECT')")
    public String list() {
        return "具有【用户查询】权限";
    }

    @GetMapping("/other")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public String ohter() {
        return "具有【其它功能】权限";
    }
}
