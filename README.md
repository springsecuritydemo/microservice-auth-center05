在之前文章中我们已经说过， **用户** <–>  **角色** <–> **权限**三层中，暂时不考虑权限，在这一篇，是时候把它完成了。

## 一、数据准备
首先我创建权限表，名为 `sys_permission`和角色权限中间表，名为 `sys_role_permission`：
```
-- 权限表
CREATE TABLE `sys_permission` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `alias` varchar(255) COLLATE utf8_bin DEFAULT NULL COMMENT '别名',
  `name` varchar(255) COLLATE utf8_bin DEFAULT NULL COMMENT '名称',
  `pid` int(11) DEFAULT NULL COMMENT '上级权限',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- 角色权限中间表
CREATE TABLE `sys_role_permission` (
  `role_id` int(11) NOT NULL,
  `permission_id` int(11) NOT NULL,
  PRIMARY KEY (`role_id`,`permission_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;
```
初始化数据：
```
INSERT INTO `sys_permission` VALUES('1', '超级管理员', 'ADMIN', '0');
INSERT INTO `sys_permission` VALUES('2', '用户管理', 'USER_ALL', '0');
INSERT INTO `sys_permission` VALUES('3', '用户查询', 'USER_SELECT', '2');
INSERT INTO `sys_permission` VALUES('4', '用户创建', 'USER_CREATE', '2');
INSERT INTO `sys_permission` VALUES('5', '用户编辑', 'USER_EDIT', '2');
INSERT INTO `sys_permission` VALUES('6', '用户删除', 'USER_DELETE', '2');

INSERT INTO `sys_role_permission` VALUES('1',  '1');
INSERT INTO `sys_role_permission` VALUES('2',  '2'); 
INSERT INTO `sys_role_permission` VALUES('3',  '3'); 
```
我们在准备三个用户：
- `administartor`： 超级管理员
- `admin`：普通管理员
- `pyy`：普通用户

## 二、创建 POJO、DAO
- SysPermission:
```
@Data
public class SysPermission implements Serializable{
    private static final long serialVersionUID = 7510552869226022669L;

    private int id;

    private String alias;

    private String name;

    private int pid;
}
```
- SysRolePermission：
```
@Data
public class SysRolePermission implements Serializable{

    private static final long serialVersionUID = 7081950007398765100L;
    private Integer roleId;

    private Integer permissionId;
}
```
- SysPermissionMapper:
```
@Mapper
public interface SysPermissionMapper {

    @Select("SELECT * FROM sys_permission WHERE id = #{id}")
    SysPermission selectById(Integer id);
}
```
- SysRolePermissionMapper:
```
@Mapper
public interface SysRolePermissionMapper {

    @Select("SELECT * FROM sys_role_permission WHERE role_id = #{roleId}")
    List<SysRolePermission> listByRoleId(Integer roleId);
}
```
## 三、修改`CustomUserDetailsService` 类 

重构`loadUserByUsername() `方法：根据用户ID查询用户角色，再根据用户角色查询用户拥有权限，最终将用户权限信息，添加到 `authorities` 集合中。
```
@Service("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private SysUserService userService;

    @Autowired
    private SysRoleService roleService;

    @Autowired
    private SysUserRoleService userRoleService;

    @Autowired
    private SysRolePermissionMapper rolePermissionMapper;

    @Autowired
    private SysPermissionMapper permissionMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        // 从数据库中取出用户信息
        SysUser user = userService.selectByName(username);

        // 判断用户是否存在
        if(user == null) {
            throw new UsernameNotFoundException("用户名不存在");
        }

        // 添加权限
        List<SysUserRole> userRoles = userRoleService.listByUserId(user.getId());
        for (SysUserRole userRole : userRoles) {

            SysRole role = roleService.selectById(userRole.getRoleId());

            List<SysRolePermission> rolePermissions = rolePermissionMapper.listByRoleId(role.getId());
            for (SysRolePermission rolePermission : rolePermissions) {
                SysPermission permission = permissionMapper.selectById(rolePermission.getPermissionId());

                authorities.add(new SimpleGrantedAuthority(permission.getName()));
            }
        }

        // 返回UserDetails实现类
        return new User(user.getName(), user.getPassword(),
                true,
                true,
                true,
                true,
                authorities);
    }
}
```
## 四、编写测试 UserController 接口类
我们这里采用 `@PreAuthorize("hasRole('ROLE_ADMIN')")`基于表达式的权限控制。

Spring Security允许我们在定义URL访问或方法访问所应有的权限时使用Spring EL表达式，在定义所需的访问权限时如果对应的表达式返回结果为true则表示拥有对应的权限，反之则无。
|表达式 | 描述|
|--|--|
|hasRole([role]) |当前用户是否拥有指定角色。|
|hasAnyRole([role1,role2])|多个角色是一个以逗号进行分隔的字符串。如果当前用户拥有指定角色中的任意一个则返回true。|
|hasAuthority([auth])|等同于hasRole
|hasAnyAuthority([auth1,auth2])|等同于hasAnyRole
|Principle|代表当前用户的principle对象
|authentication|直接从SecurityContext获取的当前Authentication对象
|permitAll|总是返回true，表示允许所有的
|denyAll|总是返回false，表示拒绝所有的
|isAnonymous()|当前用户是否是一个匿名用户
|isRememberMe()|表示当前用户是否是通过Remember-Me自动登录的
|isAuthenticated()|表示当前用户是否已经登录认证成功了。
|isFullyAuthenticated()|如果当前用户既不是一个匿名用户，同时又不是通过Remember-Me自动登录的，则返回true。
```
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

```

我们这里使用 `hasAnyRole('ADMIN','USER_ALL','USER_EDIT')` ，但参数却不是真正的 `角色标识`，而是对应的具体`权限标识`。这样实现更加精确的权限控制。

通过查看 `hasAnyRole`源码，我们发现系统在做校验是默认会加一个角色前缀：`private String defaultRolePrefix = "ROLE_";`
![](https://upload-images.jianshu.io/upload_images/11464886-34b92b271f9cc5f6.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
我们这里不需要，所以需要在 `WebSecurityConfig` 中通过配置去掉这个默认前缀。
```
    @Bean
    GrantedAuthorityDefaults grantedAuthorityDefaults() {
        // Remove the ROLE_ prefix
        return new GrantedAuthorityDefaults("");
    }
```
## 五、修改index.html：
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>
    <h1>登陆成功</h1>
    <a href="/createUser">用户添加</a>
    <a href="/updateUser">用户修改</a>
    <a href="/delUser">用户删除</a>
    <a href="/users">用户查询</a>

    <a href="/other">其它权限</a>

    <button onclick="window.location.href='/logout'">退出登录</button>
</body>
</html>

```
截止到这里我们的权限配置已经完成，可以开始测试了

## 六、运行程序
用户角色权限关系：
|用户 |角色 |权限|
|--|--|--|
|administrator|超级管理员|系统所有权限|
|admin|普通管理员|用户管理（CRUD）|
|pyy|普通用户|用户查询|

分别使用不同的用户身份登录系统，查看对应操作权限：
![](https://upload-images.jianshu.io/upload_images/11464886-d7fd40480e745768.gif?imageMogr2/auto-orient/strip)


同时测试会发现，我们已经完成了权限的控制功能。但是有一个问题，当用户没有权限访问对应接口时，系统默认抛出 403 错误吗，调整的一个默认的错误页面。

但实际开发中我们更希望，当用户没有权限访问时，我们可以自定义403错误消息处理。

## 七、自定义Spring Security 403返回消息
自定义处理类 `CustomAccessDeniedHandler`
```
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        response.setStatus(HttpStatus.FORBIDDEN.value());
        Result result = new Result(403, "无权限访问");
        response.getWriter().write(JSON.toJSONString(result));
    }
}
```
在 `WebSecurityConfig`中添加 拒绝访问处理配置：
```
    // 拒绝访问处理器
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new CustomAccessDeniedHandler();
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                // 如果有允许匿名的url，填在下面
                .antMatchers("/vCode").permitAll()
                .anyRequest().authenticated()
                // 拒绝访问错误处理
                .and().exceptionHandling().accessDeniedHandler(accessDeniedHandler())
                // 设置登陆页
                .and()
                .formLogin().loginPage("/login")
                // 设置登陆成功url
                .defaultSuccessUrl("/").permitAll()
                // 设置登录失败url
                .failureUrl("/login/error")
                // 自定义登陆用户名和密码参数，默认为username和password
//                .usernameParameter("username")
//                .passwordParameter("password")
                // 指定authenticationDetailsSource
                .authenticationDetailsSource(authenticationDetailsSource)
                .and()
                // 添加图片验证码过滤器
                //.addFilterBefore(new VerifyFilter(redisTemplate, prefix), UsernamePasswordAuthenticationFilter.class)
                .logout().permitAll()
                // 自动登录
                .and().rememberMe()
                .tokenRepository(persistentTokenRepository())
                // 有效时间，单位：s
                .tokenValiditySeconds(60)
                .userDetailsService(userDetailsService);

        // 关闭CSRF跨域
        http.csrf().disable();
    }
```
**重新启动测试：**

![](https://upload-images.jianshu.io/upload_images/11464886-7bd266ec5529aa5f.gif?imageMogr2/auto-orient/strip)

## 思考
我们这里只是简单使用SpringSecurity完成了权限的控制，具体数据库表设计可能不是很完善，但大体结构都是有的，如果想要在项目中应用，可以根据自己业务需求自行扩展。这里给出一个有关权限管理表设计参考：
![](https://upload-images.jianshu.io/upload_images/11464886-ab5e3f94886e99f2.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
```
-- ----------------------------
-- Table structure for menu
-- ----------------------------
DROP TABLE IF EXISTS `menu`;
CREATE TABLE `menu` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT 'ID',
  `create_time` datetime DEFAULT NULL COMMENT '创建日期',
  `i_frame` bit(1) DEFAULT NULL COMMENT '是否外链',
  `name` varchar(255) DEFAULT NULL COMMENT '菜单名称',
  `component` varchar(255) DEFAULT NULL COMMENT '组件',
  `pid` bigint(20) NOT NULL COMMENT '上级菜单ID',
  `sort` bigint(20) NOT NULL COMMENT '排序',
  `icon` varchar(255) DEFAULT NULL COMMENT '图标',
  `path` varchar(255) DEFAULT NULL COMMENT '链接地址',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=41 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of menu
-- ----------------------------
INSERT INTO `menu` VALUES ('1', '2019-07-23 15:11:29', '\0', '系统管理', null, '0', '1', 'system', 'system');
INSERT INTO `menu` VALUES ('2', '2019-07-23 15:14:44', '\0', '用户管理', '/system/user/index', '1', '2', 'peoples', 'user');
INSERT INTO `menu` VALUES ('3', '2019-07-23 15:16:07', '\0', '角色管理', '/system/role/index', '1', '3', 'role', 'role');
INSERT INTO `menu` VALUES ('4', '2019-07-23 15:16:45', '\0', '权限管理', '/system/permission/index', '1', '4', 'permission', 'permission');
INSERT INTO `menu` VALUES ('5', '2019-07-23 15:17:28', '\0', '菜单管理', '/system/menu/index', '1', '5', 'menu', 'menu');



-- ----------------------------
-- Table structure for permission
-- ----------------------------
DROP TABLE IF EXISTS `permission`;
CREATE TABLE `permission` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT 'ID',
  `alias` varchar(255) DEFAULT NULL COMMENT '别名',
  `create_time` datetime DEFAULT NULL COMMENT '创建日期',
  `name` varchar(255) DEFAULT NULL COMMENT '名称',
  `pid` int(11) NOT NULL COMMENT '上级权限',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=55 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of permission
-- ----------------------------
INSERT INTO `permission` VALUES ('1', '超级管理员', '2019-07-23 12:27:48', 'ADMIN', '0');
INSERT INTO `permission` VALUES ('2', '用户管理', '2019-07-23 12:28:19', 'USER_ALL', '0');
INSERT INTO `permission` VALUES ('3', '用户查询', '2019-07-23 12:31:35', 'USER_SELECT', '2');
INSERT INTO `permission` VALUES ('4', '用户创建', '2019-07-23 12:31:35', 'USER_CREATE', '2');
INSERT INTO `permission` VALUES ('5', '用户编辑', '2019-07-23 12:31:35', 'USER_EDIT', '2');
INSERT INTO `permission` VALUES ('6', '用户删除', '2019-07-23 12:31:35', 'USER_DELETE', '2');
INSERT INTO `permission` VALUES ('7', '角色管理', '2019-07-23 12:28:19', 'ROLES_ALL', '0');
INSERT INTO `permission` VALUES ('8', '角色查询', '2019-07-23 12:31:35', 'ROLES_SELECT', '7');
INSERT INTO `permission` VALUES ('10', '角色创建', '2019-07-23 20:10:16', 'ROLES_CREATE', '7');
INSERT INTO `permission` VALUES ('11', '角色编辑', '2019-07-23 20:10:42', 'ROLES_EDIT', '7');
INSERT INTO `permission` VALUES ('12', '角色删除', '2019-07-23 20:11:07', 'ROLES_DELETE', '7');
INSERT INTO `permission` VALUES ('13', '权限管理', '2019-07-23 20:11:37', 'PERMISSION_ALL', '0');
INSERT INTO `permission` VALUES ('14', '权限查询', '2019-07-23 20:11:55', 'PERMISSION_SELECT', '13');
INSERT INTO `permission` VALUES ('15', '权限创建', '2019-07-23 20:14:10', 'PERMISSION_CREATE', '13');
INSERT INTO `permission` VALUES ('16', '权限编辑', '2019-07-23 20:15:44', 'PERMISSION_EDIT', '13');
INSERT INTO `permission` VALUES ('17', '权限删除', '2019-07-23 20:15:59', 'PERMISSION_DELETE', '13');

-- ----------------------------
-- Table structure for role
-- ----------------------------
DROP TABLE IF EXISTS `role`;
CREATE TABLE `role` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT 'ID',
  `create_time` datetime DEFAULT NULL COMMENT '创建日期',
  `name` varchar(255) NOT NULL COMMENT '名称',
  `remark` varchar(255) DEFAULT NULL COMMENT '备注',
  `data_scope` varchar(255) DEFAULT NULL,
  `level` int(255) DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of role
-- ----------------------------
INSERT INTO `role` VALUES ('1', '2019-07-23 11:04:37', '超级管理员', '系统所有权', '全部', '1');
INSERT INTO `role` VALUES ('2', '2019-07-23 13:09:06', '普通用户', '用于测试菜单与权限', '自定义', '3');
INSERT INTO `role` VALUES ('3', '2019-07-23 14:16:15', '普通管理员', '普通管理员级别为2，使用该角色新增用户时只能赋予比普通管理员级别低的角色', '自定义', '2');


-- ----------------------------
-- Table structure for roles_menus
-- ----------------------------
DROP TABLE IF EXISTS `roles_menus`;
CREATE TABLE `roles_menus` (
  `menu_id` bigint(20) NOT NULL COMMENT '菜单ID',
  `role_id` bigint(20) NOT NULL COMMENT '角色ID',
  PRIMARY KEY (`menu_id`,`role_id`) USING BTREE,
  KEY `FKcngg2qadojhi3a651a5adkvbq` (`role_id`) USING BTREE,
  CONSTRAINT `FKcngg2qadojhi3a651a5adkvbq` FOREIGN KEY (`role_id`) REFERENCES `role` (`id`),
  CONSTRAINT `FKq1knxf8ykt26we8k331naabjx` FOREIGN KEY (`menu_id`) REFERENCES `menu` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;



-- ----------------------------
-- Table structure for roles_permissions
-- ----------------------------
DROP TABLE IF EXISTS `roles_permissions`;
CREATE TABLE `roles_permissions` (
  `role_id` bigint(20) NOT NULL COMMENT '角色ID',
  `permission_id` bigint(20) NOT NULL COMMENT '权限ID',
  PRIMARY KEY (`role_id`,`permission_id`) USING BTREE,
  KEY `FKboeuhl31go7wer3bpy6so7exi` (`permission_id`) USING BTREE,
  CONSTRAINT `FK4hrolwj4ned5i7qe8kyiaak6m` FOREIGN KEY (`role_id`) REFERENCES `role` (`id`),
  CONSTRAINT `FKboeuhl31go7wer3bpy6so7exi` FOREIGN KEY (`permission_id`) REFERENCES `permission` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


-- ----------------------------
-- Table structure for user
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT 'ID',
  `avatar` varchar(255) DEFAULT NULL COMMENT '头像地址',
  `create_time` datetime DEFAULT NULL COMMENT '创建日期',
  `email` varchar(255) DEFAULT NULL COMMENT '邮箱',
  `enabled` bigint(20) DEFAULT NULL COMMENT '状态：1启用、0禁用',
  `password` varchar(255) DEFAULT NULL COMMENT '密码',
  `username` varchar(255) DEFAULT NULL COMMENT '用户名',
  `last_password_reset_time` datetime DEFAULT NULL COMMENT '最后修改密码的日期',
  `dept_id` bigint(20) DEFAULT NULL,
  `phone` varchar(255) DEFAULT NULL,
  `job_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE KEY `UK_kpubos9gc2cvtkb0thktkbkes` (`email`) USING BTREE,
  UNIQUE KEY `username` (`username`) USING BTREE,
  KEY `FK5rwmryny6jthaaxkogownknqp` (`dept_id`),
  KEY `FKfftoc2abhot8f2wu6cl9a5iky` (`job_id`),
  CONSTRAINT `FK5rwmryny6jthaaxkogownknqp` FOREIGN KEY (`dept_id`) REFERENCES `dept` (`id`),
  CONSTRAINT `FKfftoc2abhot8f2wu6cl9a5iky` FOREIGN KEY (`job_id`) REFERENCES `job` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8;


-- ----------------------------
-- Table structure for users_roles
-- ----------------------------
DROP TABLE IF EXISTS `users_roles`;
CREATE TABLE `users_roles` (
  `user_id` bigint(20) NOT NULL COMMENT '用户ID',
  `role_id` bigint(20) NOT NULL COMMENT '角色ID',
  PRIMARY KEY (`user_id`,`role_id`) USING BTREE,
  KEY `FKq4eq273l04bpu4efj0jd0jb98` (`role_id`) USING BTREE,
  CONSTRAINT `users_roles_ibfk_1` FOREIGN KEY (`role_id`) REFERENCES `role` (`id`),
  CONSTRAINT `users_roles_ibfk_2` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
```

