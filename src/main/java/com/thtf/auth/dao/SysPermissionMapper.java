package com.thtf.auth.dao;

import com.thtf.auth.model.SysPermission;
import com.thtf.auth.model.SysRole;
import com.thtf.auth.model.SysUserRole;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

import java.util.List;

/**
 * ========================
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/7/25 10:34
 * Version: v1.0
 * ========================
 */
@Mapper
public interface SysPermissionMapper {

    @Select("SELECT * FROM sys_permission WHERE id = #{id}")
    SysPermission selectById(Integer id);
}
