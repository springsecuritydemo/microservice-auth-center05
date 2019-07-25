package com.thtf.auth.dao;

import com.thtf.auth.model.SysPermission;
import com.thtf.auth.model.SysRolePermission;
import com.thtf.auth.model.SysUserRole;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

import java.util.List;

/**
 * ========================
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/7/25 10:36
 * Version: v1.0
 * ========================
 */
@Mapper
public interface SysRolePermissionMapper {

    @Select("SELECT * FROM sys_role_permission WHERE role_id = #{roleId}")
    List<SysRolePermission> listByRoleId(Integer roleId);
}
