-- =================================================================
-- NEC 核心表结构
-- =================================================================

-- 创建序列
CREATE SEQUENCE IF NOT EXISTS sys_user_id_seq START WITH 1 INCREMENT BY 1;
CREATE SEQUENCE IF NOT EXISTS sys_role_id_seq START WITH 1 INCREMENT BY 1;
CREATE SEQUENCE IF NOT EXISTS sys_permission_id_seq START WITH 1 INCREMENT BY 1;
CREATE SEQUENCE IF NOT EXISTS sys_user_role_id_seq START WITH 1 INCREMENT BY 1;
CREATE SEQUENCE IF NOT EXISTS sys_role_permission_id_seq START WITH 1 INCREMENT BY 1;
CREATE SEQUENCE IF NOT EXISTS sys_totp_config_id_seq START WITH 1 INCREMENT BY 1;
CREATE SEQUENCE IF NOT EXISTS sys_config_id_seq START WITH 1 INCREMENT BY 1;
CREATE SEQUENCE IF NOT EXISTS sys_auth_provider_config_id_seq START WITH 1 INCREMENT BY 1;

-- 用户表
CREATE TABLE IF NOT EXISTS sys_user (
                                        id BIGINT PRIMARY KEY DEFAULT nextval('sys_user_id_seq'),
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    phone VARCHAR(255),
    password VARCHAR(255) NOT NULL,
    nickname VARCHAR(255),
    avatar VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP,
    totp_enabled BOOLEAN NOT NULL DEFAULT false
    );

-- 角色表
CREATE TABLE IF NOT EXISTS sys_role (
                                        id BIGINT PRIMARY KEY DEFAULT nextval('sys_role_id_seq'),
    name VARCHAR(255) NOT NULL,
    code VARCHAR(255) NOT NULL,
    description VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

-- 权限表
CREATE TABLE IF NOT EXISTS sys_permission (
                                              id BIGINT PRIMARY KEY DEFAULT nextval('sys_permission_id_seq'),
    name VARCHAR(255) NOT NULL,
    code VARCHAR(255) NOT NULL,
    description VARCHAR(255),
    resource_type VARCHAR(50) NOT NULL DEFAULT 'API',
    resource_path VARCHAR(255),
    method VARCHAR(50),
    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

-- 用户角色关联表
CREATE TABLE IF NOT EXISTS sys_user_role (
                                             id BIGINT PRIMARY KEY DEFAULT nextval('sys_user_role_id_seq'),
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_user_role_user FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_role_role FOREIGN KEY (role_id) REFERENCES sys_role(id) ON DELETE CASCADE,
    CONSTRAINT uk_user_role UNIQUE (user_id, role_id)
    );

-- 角色权限关联表
CREATE TABLE IF NOT EXISTS sys_role_permission (
                                                   id BIGINT PRIMARY KEY DEFAULT nextval('sys_role_permission_id_seq'),
    role_id BIGINT NOT NULL,
    permission_id BIGINT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_role_permission_role FOREIGN KEY (role_id) REFERENCES sys_role(id) ON DELETE CASCADE,
    CONSTRAINT fk_role_permission_permission FOREIGN KEY (permission_id) REFERENCES sys_permission(id) ON DELETE CASCADE,
    CONSTRAINT uk_role_permission UNIQUE (role_id, permission_id)
    );

-- TOTP配置表
CREATE TABLE IF NOT EXISTS sys_totp_config (
                                               id BIGINT PRIMARY KEY DEFAULT nextval('sys_totp_config_id_seq'),
    user_id BIGINT NOT NULL,
    secret_key VARCHAR(255) NOT NULL,
    qr_code_url VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_totp_config_user FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
    CONSTRAINT uk_totp_config_user UNIQUE (user_id)
    );

-- 系统配置表
CREATE TABLE IF NOT EXISTS sys_config (
                                          id BIGINT PRIMARY KEY DEFAULT nextval('sys_config_id_seq'),
    config_key VARCHAR(255) NOT NULL,
    config_value VARCHAR(255) NOT NULL,
    description VARCHAR(255),
    type VARCHAR(50) NOT NULL DEFAULT 'STRING',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uk_config_key UNIQUE (config_key)
    );

-- 认证提供商配置表
CREATE TABLE IF NOT EXISTS sys_auth_provider_config (
                                                        id BIGINT PRIMARY KEY DEFAULT nextval('sys_auth_provider_config_id_seq'),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    client_id VARCHAR(255),
    client_secret VARCHAR(255),
    issuer_uri VARCHAR(255),
    authorization_uri VARCHAR(255),
    token_uri VARCHAR(255),
    user_info_uri VARCHAR(255),
    jwk_set_uri VARCHAR(255),
    redirect_uri VARCHAR(255),
    cas_server_url VARCHAR(255),
    cas_service_url VARCHAR(255),
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_user_username ON sys_user(username);
CREATE INDEX IF NOT EXISTS idx_user_email ON sys_user(email);
CREATE INDEX IF NOT EXISTS idx_user_status ON sys_user(status);
CREATE INDEX IF NOT EXISTS idx_role_code ON sys_role(code);
CREATE INDEX IF NOT EXISTS idx_role_status ON sys_role(status);
CREATE INDEX IF NOT EXISTS idx_permission_code ON sys_permission(code);
CREATE INDEX IF NOT EXISTS idx_permission_status ON sys_permission(status);
CREATE INDEX IF NOT EXISTS idx_user_role_user_id ON sys_user_role(user_id);
CREATE INDEX IF NOT EXISTS idx_user_role_role_id ON sys_user_role(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permission_role_id ON sys_role_permission(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permission_permission_id ON sys_role_permission(permission_id);
CREATE INDEX IF NOT EXISTS idx_totp_config_user_id ON sys_totp_config(user_id);
CREATE INDEX IF NOT EXISTS idx_config_key ON sys_config(config_key);
CREATE INDEX IF NOT EXISTS idx_auth_provider_enabled ON sys_auth_provider_config(enabled);

-- 添加表注释
COMMENT ON TABLE sys_user IS '用户表 - 系统核心实体，用于用户认证和授权';
COMMENT ON TABLE sys_role IS '角色表 - 定义系统中的角色信息，用于权限管理';
COMMENT ON TABLE sys_permission IS '权限表 - 定义系统中的权限信息，用于权限管理';
COMMENT ON TABLE sys_user_role IS '用户角色关联表 - 实现用户与角色的多对多关系映射';
COMMENT ON TABLE sys_role_permission IS '角色权限关联表 - 实现角色与权限的多对多关系映射';
COMMENT ON TABLE sys_totp_config IS 'TOTP配置表 - 用于存储用户双因素认证的配置信息';
COMMENT ON TABLE sys_config IS '系统配置表 - 用于存储系统级别的配置项';
COMMENT ON TABLE sys_auth_provider_config IS '认证提供商配置表 - 用于存储OIDC、CAS等认证提供商的配置信息';

-- 初始化配置
INSERT INTO sys_config (config_key, config_value, description, type) VALUES ('login:openRegistration', 'false', '是否允许注册', 'BOOLEAN');
INSERT INTO sys_config (config_key, config_value, description) VALUES ('login:enabledMethods', 'username,email', '登陆方式');

-- 初始化管理员信息
INSERT INTO sys_role (name, code, description) VALUES ('管理员', 'ADMIN', '管理员角色');
INSERT INTO sys_user (username, email, phone, password, nickname, avatar, last_login_at) VALUES ('admin', 'admin@temp.a', null, '$2a$10$6NCWQvA/bGz.MtnXEKpIe.cLaNO9F2ut/iHHVGlBi0oThwPuho.WC', '管理员', null, null);

DO $$
DECLARE
userId BIGINT;
    roleId BIGINT;
BEGIN

SELECT id INTO userId FROM sys_user WHERE username = 'admin';
SELECT id INTO roleId FROM sys_role WHERE code = 'ADMIN';

INSERT INTO sys_user_role (user_id, role_id) VALUES (userId, roleId);
END $$;

-- =================================================================
-- ProxyManagePanel 业务表结构 (节点、网站、证书)
-- =================================================================

-- 创建序列
CREATE SEQUENCE IF NOT EXISTS p_node_id_seq START WITH 1 INCREMENT BY 1;
CREATE SEQUENCE IF NOT EXISTS p_website_id_seq START WITH 1 INCREMENT BY 1;
CREATE SEQUENCE IF NOT EXISTS p_certificate_id_seq START WITH 1 INCREMENT BY 1;

-- 1. 节点表 (p_node)
CREATE TABLE IF NOT EXISTS p_node (
                                      id BIGINT PRIMARY KEY DEFAULT nextval('p_node_id_seq'),
    name VARCHAR(100) NOT NULL,
    agent_id VARCHAR(64) NOT NULL,
    secret_key VARCHAR(128) NOT NULL,
    ip_addr VARCHAR(50),
    type VARCHAR(20) DEFAULT 'NGINX',
    status INT DEFAULT 0,
    os_info TEXT,
    version VARCHAR(50),
    last_heartbeat TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uk_node_agent_id UNIQUE (agent_id),
    CONSTRAINT uk_node_secret_key UNIQUE (secret_key)
    );

-- 2. 证书表 (p_certificate)
CREATE TABLE IF NOT EXISTS p_certificate (
                                             id BIGINT PRIMARY KEY DEFAULT nextval('p_certificate_id_seq'),
    name VARCHAR(100) NOT NULL,
    domain VARCHAR(255),
    issuer VARCHAR(100),
    cert_content TEXT,
    key_content TEXT,
    provider VARCHAR(20) DEFAULT 'MANUAL',
    expire_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

-- 3. 网站表 (p_website)
CREATE TABLE IF NOT EXISTS p_website (
                                         id BIGINT PRIMARY KEY DEFAULT nextval('p_website_id_seq'),
    node_id BIGINT NOT NULL,
    domains TEXT NOT NULL,
    target_host VARCHAR(255) NOT NULL,
    target_port INT NOT NULL,
    ssl_type VARCHAR(20) DEFAULT 'OFF',
    cert_id BIGINT,
    force_https BOOLEAN DEFAULT false,
    advanced_config TEXT,
    enabled BOOLEAN DEFAULT true,
    sync_status VARCHAR(20) DEFAULT 'PENDING',
    last_error TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_website_node FOREIGN KEY (node_id) REFERENCES p_node(id) ON DELETE CASCADE,
    CONSTRAINT fk_website_cert FOREIGN KEY (cert_id) REFERENCES p_certificate(id) ON DELETE SET NULL
    );

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_node_status ON p_node(status);
CREATE INDEX IF NOT EXISTS idx_node_secret_key ON p_node(secret_key);
CREATE INDEX IF NOT EXISTS idx_certificate_expire_at ON p_certificate(expire_at);
CREATE INDEX IF NOT EXISTS idx_website_node_id ON p_website(node_id);
CREATE INDEX IF NOT EXISTS idx_website_cert_id ON p_website(cert_id);
CREATE INDEX IF NOT EXISTS idx_website_enabled ON p_website(enabled);

-- 添加表注释
COMMENT ON TABLE p_node IS '节点表 - 记录连接到 Panel 的 Agent 服务器节点信息';
COMMENT ON TABLE p_certificate IS 'SSL证书表 - 存储用户上传或自动申请的SSL证书文件内容';
COMMENT ON TABLE p_website IS '网站表 - 记录 Nginx/Caddy 的反向代理配置规则';