import json
from pathlib import Path


STACK_SERVICES = [
    "web",
    "filebrowser",
    "phpmyadmin",
    "db",
    "pg",
    "adminer",
    "cron",
    "sftp",
    "smtp-relay",
]


def build_account_runtime(account, public_host="127.0.0.1", port_base=18000):
    import secrets
    account_id = int(account["id"])
    slot = port_base + (account_id * 10)
    username = account["username"]
    base = {
        "public_host": public_host,
        "web_port": slot,
        "filebrowser_port": slot + 1,
        "phpmyadmin_port": slot + 2,
        "mailpit_port": slot + 3,
        "db_port": slot + 4,
        "sftp_port": slot + 5,
        "smtp_port": slot + 6,
        "pg_port": slot + 7,
        "adminer_port": slot + 8,
        "sftp_host": public_host,
        "sftp_user": username,
        "web_url": f"http://web-{username}.localhost",
        "filebrowser_url": f"http://files-{username}.localhost",
        "phpmyadmin_url": f"http://pma-{username}.localhost",
        "adminer_url": f"http://adminer-{username}.localhost",
        "webmail_url": f"http://mail-{username}.localhost",
        "mailpit_url": f"http://mail-{username}.localhost",
        "db_host": public_host,
        "db_name": "{}_app".format(username),
        "db_user": "{}_app".format(username),
        "db_password": "dev-db-password-change-me",
        "db_root_password": "dev-root-password-change-me",
        "sftp_password": "dev-sftp-password",
        "filebrowser_password": "dev-fb-password",
        "filebrowser_secret_path": f"fb_{secrets.token_hex(16)}",
        "phpmyadmin_secret_path": f"pma_{secrets.token_hex(16)}",
    }
    
    if public_host != "127.0.0.1":
        base["filebrowser_url"] = f"http://files.{username}.{public_host}"
        base["phpmyadmin_url"] = f"http://pma.{username}.{public_host}"
        base["adminer_url"] = f"http://adminer.{username}.{public_host}"
        base["webmail_url"] = f"http://mail.{username}.{public_host}"
        base["mailpit_url"] = f"http://mail.{username}.{public_host}"

    return base


def account_paths(account):
    base = Path(account["base_path"])
    return {
        "base": base,
        "domains": base / "domains",
        "databases": base / "databases",
        "mail": base / "mail",
        "backups": base / "backups",
        "git": base / "git",
        "ssl": base / "ssl",
        "runtime": base / ".runtime",
        "stack": base / ".runtime" / "stack",
        "compose": base / ".runtime" / "stack" / "docker-compose.yml",
        "account_json": base / "account.json",
        "apache_vhosts": base / ".runtime" / "stack" / "apache-vhosts.conf",
    }


def render_account_metadata(account, plan, node, websites, runtime):
    return {
        "account_id": account["id"],
        "username": account["username"],
        "status": account["status"],
        "base_path": account["base_path"],
        "plan": {
            "id": plan["id"],
            "name": plan["name"],
            "cpu_limit": plan["cpu_limit"],
            "memory_mb": plan["memory_mb"],
            "storage_mb": plan["storage_mb"],
            "inode_limit": plan["inode_limit"],
            "max_websites": plan["max_websites"],
            "max_databases": plan["max_databases"],
            "max_mailboxes": plan["max_mailboxes"],
            "max_cron_jobs": plan["max_cron_jobs"],
            "daily_email_limit": plan["daily_email_limit"],
            "backup_retention_days": plan["backup_retention_days"],
        },
        "node": {
            "id": node["id"],
            "name": node["name"],
            "hostname": node["hostname"],
            "quota_backend": node["quota_backend"],
        },
        "runtime": runtime,
        "websites": [
            {
                "id": website["id"],
                "domain": website["domain"],
                "document_root": website["document_root"],
                "php_version": website["php_version"],
                "ssl_status": website["ssl_status"],
                "status": website["status"],
            }
            for website in websites
        ],
    }


def ensure_account_layout(account, plan, node, websites, runtime=None):
    runtime = runtime or build_account_runtime(account)
    paths = account_paths(account)
    for key in ["base", "domains", "databases", "mail", "backups", "git", "ssl", "runtime", "stack"]:
        paths[key].mkdir(parents=True, exist_ok=True)
        
    (paths["base"] / "pg_databases").mkdir(parents=True, exist_ok=True)

    for website in websites:
        root = Path(website["document_root"])
        root.mkdir(parents=True, exist_ok=True)
        logs = root.parent / "logs"
        tmp = root.parent / "tmp"
        logs.mkdir(parents=True, exist_ok=True)
        tmp.mkdir(parents=True, exist_ok=True)
        index = root / "index.php"
        if not index.exists():
            index.write_text(
                "<?php\n"
                "header('Content-Type: text/plain');\n"
                "echo \"MangoPanel dev site: {}\\n\";\n".format(website["domain"]),
                encoding="utf-8",
            )

    metadata = render_account_metadata(account, plan, node, websites, runtime)
    paths["account_json"].write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    (paths["stack"] / "quota.json").write_text(json.dumps(metadata["plan"], indent=2) + "\n", encoding="utf-8")
    (paths["stack"] / "filebrowser").mkdir(parents=True, exist_ok=True)
    fb_config_dir = paths["stack"] / "filebrowser-config"
    fb_config_dir.mkdir(parents=True, exist_ok=True)
    fb_branding_dir = paths["stack"] / "filebrowser-branding"
    fb_branding_dir.mkdir(parents=True, exist_ok=True)
    fb_settings = fb_config_dir / "settings.json"
    if not fb_settings.exists():
        fb_settings.write_text(
            '{\n  "port": 80,\n  "baseURL": "",\n  "address": "",\n  "log": "stdout",\n  "database": "/database/filebrowser.db",\n  "root": "/srv",\n  "branding": {\n    "name": "File Manager",\n    "disableUsedPercentage": true,\n    "files": "/branding"\n  }\n}\n',
            encoding="utf-8"
        )
    
    # Generate OLS config
    vhosts_dir = paths["stack"] / "vhosts"
    vhosts_dir.mkdir(parents=True, exist_ok=True)
    for website in websites:
        domain = website["domain"]
        domain_dir = vhosts_dir / domain
        domain_dir.mkdir(parents=True, exist_ok=True)
        (domain_dir / "vhconf.conf").write_text(render_ols_vhconf(account, website), encoding="utf-8")
        
    (paths["stack"] / "openlitespeed-httpd.conf").write_text(render_openlitespeed_httpd_config(account, websites), encoding="utf-8")
    paths["apache_vhosts"].write_text(render_apache_vhosts(account, websites), encoding="utf-8")
    (paths["stack"] / "cron").write_text(render_crontab(account), encoding="utf-8")
    
    mysql_cnf = """[mysqld]
"""
    (paths["stack"] / "mysql.cnf").write_text(mysql_cnf, encoding="utf-8")
    
    sftp_users_conf = paths["stack"] / "sftp_users.conf"
    if not sftp_users_conf.exists():
        sftp_users_conf.write_text(f"{account['username']}:{runtime['sftp_password']}:1001\n", encoding="utf-8")
        
    paths["compose"].write_text(render_compose(account, plan, websites, runtime), encoding="utf-8")
    
    # Generate custom web Dockerfile
    web_build_dir = paths["stack"] / "web"
    web_build_dir.mkdir(parents=True, exist_ok=True)
    dockerfile_content = """FROM litespeedtech/openlitespeed:latest
RUN apt-get update && apt-get install -y lsphp82 lsphp83 lsphp84 \\
    lsphp82-mysql lsphp83-mysql lsphp84-mysql \\
    lsphp82-curl lsphp83-curl lsphp84-curl \\
    && rm -rf /var/lib/apt/lists/*
"""
    (web_build_dir / "Dockerfile").write_text(dockerfile_content, encoding="utf-8")
    
    # OS User Separation: Change ownership and permissions (Linux production only)
    import sys, subprocess
    if sys.platform.startswith("linux"):
        uid = 5000 + int(account["id"])
        try:
            subprocess.run(["chown", "-R", f"{uid}:{uid}", str(paths["base"])], check=True)
            subprocess.run(["chmod", "750", str(paths["base"])], check=True)
        except Exception as e:
            print(f"Warning: failed to chown/chmod account base path: {e}")
        
    return paths


def render_apache_vhosts(account, websites):
    blocks = []
    for index, website in enumerate(websites):
        root = container_path(account, website["document_root"])
        logs_dir = container_path(account, str(Path(website["document_root"]).parent / "logs"))
        blocks.append(
            """
<VirtualHost *:80>
  ServerName {domain}
  ServerAlias www.{domain}
  DocumentRoot "{root}"

  <Directory "{root}">
    Options Indexes FollowSymLinks
    AllowOverride All
    Require all granted
  </Directory>

  ErrorLog "{logs_dir}/error.log"
  CustomLog "{logs_dir}/access.log" combined
</VirtualHost>
""".strip().format(domain=website["domain"], root=root, logs_dir=logs_dir)
        )
    if not blocks:
        fallback_root = container_path(account, str(Path(account["base_path"]) / "domains" / "default" / "public_html"))
        blocks.append(
            """
<VirtualHost *:80>
  ServerName {username}.mango.test
  DocumentRoot "{root}"
  <Directory "{root}">
    Options Indexes FollowSymLinks
    AllowOverride All
    Require all granted
  </Directory>
</VirtualHost>
""".strip().format(username=account["username"], root=fallback_root)
        )
    return "\n\n".join(blocks) + "\n"


def container_path(account, host_path):
    base = Path(account["base_path"]).resolve()
    path = Path(host_path).resolve()
    try:
        rel = path.relative_to(base)
    except ValueError:
        return str(path)
    return str(Path("/home") / account["username"] / rel)


def render_openlitespeed_httpd_config(account, websites):
    base_config = """
serverName                       MangoPanel
user                             nobody
group                            nogroup
priority                         0
autoRestart                      1
chrootPath                       /
enableChroot                     0
inMemBufSize                     60M
swappingDir                      /tmp/lshttpd/swap
autoFix503                       1
gracefulRestartTimeout           300
mime                             conf/mime.properties
showVersionNumber                0
adminEmails                      root@localhost
indexFiles                       index.html, index.php
disableWebAdmin                  0

errorlog $SERVER_ROOT/logs/error.log {
    logLevel             DEBUG
    debugLevel           0
    rollingSize          10M
    enableStderrLog      1
}

accessLog $SERVER_ROOT/logs/access.log {
    rollingSize          10M
    keepDays             30
    compressArchive      0
    logReferer           1
    logUserAgent         1
}

expires {
    enableExpires           1
    expiresByType           image/*=A604800,text/css=A604800,application/x-javascript=A604800,application/javascript=A604800,font/*=A604800,application/x-font-ttf=A604800
}

tuning{
    maxConnections               10000
    maxSSLConnections            10000
    connTimeout                  300
    maxKeepAliveReq              10000
    smartKeepAlive               0
    keepAliveTimeout             5
    sndBufSize                   0
    rcvBufSize                   0
    gzipStaticCompressLevel      6
    gzipMaxFileSize              10M
    eventDispatcher              best
    maxCachedFileSize            4096
    totalInMemCacheSize          20M
    maxMMapFileSize              256K
    totalMMapCacheSize           40M
    useSendfile                  1
    fileETag                     28
    SSLCryptoDevice              null
    maxReqURLLen                 32768
    maxReqHeaderSize             65536
    maxReqBodySize               2047M
    maxDynRespHeaderSize         32768
    maxDynRespSize               2047M
    enableGzipCompress           1
    enableBrCompress             4
    enableDynGzipCompress        1
    gzipCompressLevel            6
    brStaticCompressLevel        6
    compressibleTypes            default
    gzipAutoUpdateStatic         1
    gzipMinFileSize              300
    quicEnable                   1
    quicShmDir                   /dev/shm
}

fileAccessControl{
    followSymbolLink                            1
    checkSymbolLink                             0
    requiredPermissionMask                      000
    restrictedPermissionMask                    000
}

perClientConnLimit{
    staticReqPerSec                          0
    dynReqPerSec                             0
    outBandwidth                             0
    inBandwidth                              0
    softLimit                                10000
    hardLimit                                10000
    gracePeriod                              15
    banPeriod                                300
}

CGIRLimit{
    maxCGIInstances                         20
    minUID                                  11
    minGID                                  10
    priority                                0
    CPUSoftLimit                            10
    CPUHardLimit                            50
    memSoftLimit                            2047M
    memHardLimit                            2047M
    procSoftLimit                           400
    procHardLimit                           450
}

accessControl{
    allow                                   ALL
    deny
}

module cache {
    ls_enabled          1
    checkPrivateCache   1
    checkPublicCache    1
    maxCacheObjSize     10000000
    maxStaleAge         200
    qsCache             1
    reqCookieCache      1
    respCookieCache     1
    ignoreReqCacheCtrl  1
    ignoreRespCacheCtrl 0
    enableCache         0
    expireInSeconds     3600
    enablePrivateCache  0
    privateExpireInSeconds 3600
}
"""
    blocks = [base_config]
    
    for website in websites:
        domain = website["domain"]
        safe_domain = domain.replace(".", "_").replace("-", "_")
        PHP_VERSIONS = ["8.2", "8.3", "8.4"]
        supported_php = {"82", "83", "84"}
        php_raw = str(website.get("php_version", "8.2"))
        php_ver = php_raw.replace(".", "")
        if php_ver not in supported_php:
            php_ver = "82"

        blocks.append(
            f"""
extprocessor lsphp_{safe_domain} {{
  type                    lsapi
  address                 uds://tmp/lshttpd/lsphp_{safe_domain}.sock
  maxConns                10
  env                     PHP_LSAPI_CHILDREN=10
  env                     LSAPI_AVOID_FORK=200M
  initTimeout             60
  retryTimeout            0
  persistConn             1
  respBuffer              0
  autoStart               1
  path                    /usr/local/lsws/lsphp{php_ver}/bin/lsphp
  backlog                 100
  instances               1
  priority                0
  memSoftLimit            0
  memHardLimit            0
  procSoftLimit           1400
  procHardLimit           1500
}}
""".strip()
        )

    for website in websites:
        domain = website["domain"]
        root = container_path(account, website["document_root"])
        blocks.append(
            """
virtualHost {domain} {{
  vhRoot                  {root}
  configFile              $SERVER_ROOT/conf/vhosts/{domain}/vhconf.conf
  allowSymbolLink         2
  enableScript            1
  restrained              1
  setUIDMode              0
}}
""".strip().format(domain=domain, root=root)
        )
    
    if websites:
        maps = []
        for i, w in enumerate(websites):
            if i == 0:
                maps.append(f"map                     {w['domain']} {w['domain']}, *")
            else:
                maps.append(f"map                     {w['domain']} {w['domain']}")
        maps_str = "\n  ".join(maps)
        blocks.append(
            f"""
listener http {{
  address                 *:80
  secure                  0
  {maps_str}
}}
""".strip()
        )
    return "\n\n".join(blocks) + "\n"


def render_ols_vhconf(account, website):
    domain = website["domain"]
    safe_domain = domain.replace(".", "_").replace("-", "_")

    # Ensure PHP version is one of the supported versions (82, 83, 84)
    supported_php = {"82", "83", "84"}
    php_raw = str(website.get("php_version", "8.2"))
    php_ver = php_raw.replace(".", "")
    if php_ver not in supported_php:
        php_ver = "82"
    doc_root = container_path(account, website["document_root"])
    base_dir = container_path(account, str(Path(website["document_root"]).parent))
    logs_dir = container_path(account, str(Path(website["document_root"]).parent / "logs"))
    return f"""
docRoot                   {doc_root}
enableGzip                1
enableBr                  1

general {{
  enableContextAC         0
}}

errorlog {logs_dir}/error.log {{
  useServer               0
  logLevel                DEBUG
  rollingSize             10M
}}

accesslog {logs_dir}/access.log {{
  useServer               0
  rollingSize             10M
  keepDays                30
}}

context / {{
  type                    NULL
  location                {doc_root}/
  allowBrowse             1
  indexFiles              index.php, index.html
  rewrite  {{
    enable                1
    autoLoadHtaccess      1
  }}
}}

scripthandler  {{
  add                     lsapi:lsphp_{safe_domain} php
}}

phpIniOverride  {{
  php_admin_value open_basedir "{base_dir}:/tmp:/var/tmp"
}}

module cache {{
  storagePath             /usr/local/lsws/cachedata
}}
"""


def render_crontab(account, cron_jobs=None):
    lines = [
        "# MangoPanel cron file for {}".format(account["username"]),
        "SHELL=/bin/sh",
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "",
    ]
    for job in cron_jobs or []:
        if job["status"] != "enabled":
            continue
        command = str(job["command"]).replace("\n", " ").strip()
        if not command:
            continue
        lines.append("{} {}".format(job["schedule"], command))
    return "\n".join(lines) + "\n"


def render_compose(account, plan, websites, runtime):
    uid = 5000 + int(account["id"])
    domains_str = ", ".join([w["domain"] for w in websites]) if websites else f"{account['username']}.mango.test"
    username = account["username"]
    base_path = account["base_path"]
    memory = "{}m".format(plan["memory_mb"])
    cpu_count = compose_cpu_limit(plan["cpu_limit"])
    storage_mb = int(plan["storage_mb"])
    inode_limit = int(plan["inode_limit"])
    backup_retention_days = int(plan["backup_retention_days"])
    default_domain = websites[0]["domain"] if websites else "{}.mango.test".format(username)
    project = "mp-{}".format(username)
    composed = """name: {project}
services:
  web:
    build: ./web
    image: mangopanel-web:latest
    container_name: mp-{username}-web
    restart: unless-stopped
    mem_limit: {memory}
    cpus: "{cpu_count}"
    pids_limit: 256
    labels:
      mangopanel.plan: "{plan_name}"
      mangopanel.storage_mb: "{storage_mb}"
      mangopanel.inode_limit: "{inode_limit}"
      mangopanel.backup_retention_days: "{backup_retention_days}"
      caddy: "http://{domains_str}"
      caddy.reverse_proxy: "{{upstreams 80}}"
    volumes:
      - {base_path}:/home/{username}
      - {base_path}/.runtime/stack/openlitespeed-httpd.conf:/usr/local/lsws/conf/httpd_config.conf:ro
      - {base_path}/.runtime/stack/vhosts:/usr/local/lsws/conf/vhosts:ro
    networks:
      - account
      - mangopanel-edge

  filebrowser:
    image: filebrowser/filebrowser:latest
    container_name: mp-{username}-filebrowser
    restart: unless-stopped
    mem_limit: 128m
    command: ["--noauth", "--baseURL", "/{filebrowser_secret_path}", "--root", "/srv", "--address", "0.0.0.0", "--port", "80", "--database", "/database/filebrowser.db"]
    environment:
      FB_BRANDING_DISABLE_USED_PERCENTAGE: "true"
      FB_BRANDING_FILES: "/branding"
    labels:
      caddy: "http://{filebrowser_domain}"
      caddy.handle_path: "/{filebrowser_secret_path}/auth/*"
      caddy.handle_path.0_rewrite: "* /api/public/tool-launch/filebrowser{{uri}}"
      caddy.handle_path.1_reverse_proxy: "host.docker.internal:8000"
      caddy.route: "/{filebrowser_secret_path}/*"
      caddy.route.0_forward_auth: "host.docker.internal:8000"
      caddy.route.0_forward_auth.uri: "/api/public/auth-verify"
      caddy.route.1_uri: "strip_prefix /{filebrowser_secret_path}"
      caddy.route.2_reverse_proxy: "{{upstreams 80}}"
    volumes:
      - {base_path}/domains:/srv/domains
      - {base_path}/databases:/srv/databases
      - {base_path}/mail:/srv/mail
      - {base_path}/backups:/srv/backups
      - {base_path}/git:/srv/git
      - {base_path}/ssl:/srv/ssl
      - {base_path}/.runtime/stack/filebrowser:/database
      - {base_path}/.runtime/stack/filebrowser-config:/config
      - {base_path}/.runtime/stack/filebrowser-branding:/branding
    networks:
      - account
      - mangopanel-edge

  phpmyadmin:
    image: phpmyadmin:latest
    container_name: mp-{username}-phpmyadmin
    restart: unless-stopped
    mem_limit: 256m
    labels:
      caddy: "http://{phpmyadmin_domain}"
      caddy.handle_path: "/{phpmyadmin_secret_path}/auth/*"
      caddy.handle_path.0_rewrite: "* /api/public/tool-launch/phpmyadmin{{uri}}"
      caddy.handle_path.1_reverse_proxy: "host.docker.internal:8000"
      caddy.route: "/{phpmyadmin_secret_path}/*"
      caddy.route.0_forward_auth: "host.docker.internal:8000"
      caddy.route.0_forward_auth.uri: "/api/public/auth-verify"
      caddy.route.1_uri: "strip_prefix /{phpmyadmin_secret_path}"
      caddy.route.2_reverse_proxy: "{{upstreams 80}}"
    environment:
      PMA_HOST: db
      PMA_USER: {db_user}
      PMA_PASSWORD: {db_password}
      PMA_ABSOLUTE_URI: "http://{phpmyadmin_domain}/{phpmyadmin_secret_path}/"
      UPLOAD_LIMIT: 256M
    networks:
      - account
      - mangopanel-edge

  db:
    image: mariadb:10.11
    container_name: mp-{username}-db
    restart: unless-stopped
    mem_limit: 512m
    labels:
      mangopanel.plan: "{plan_name}"
      mangopanel.storage_mb: "{storage_mb}"
      mangopanel.inode_limit: "{inode_limit}"
    ports:
      - "127.0.0.1:{db_port}:3306"
    environment:
      MARIADB_ROOT_PASSWORD: {db_root_password}
      MARIADB_ROOT_HOST: "%"
      MARIADB_DATABASE: {db_name}
      MARIADB_USER: {db_user}
      MARIADB_PASSWORD: {db_password}
    volumes:
      - db-data:/var/lib/mysql
      - {base_path}/.runtime/stack/mysql.cnf:/etc/mysql/conf.d/mysql.cnf:ro
    networks:
      - account
      - mangopanel-edge

  pg:
    image: postgres:16
    container_name: mp-{username}-pg
    restart: unless-stopped
    mem_limit: 512m
    ports:
      - "127.0.0.1:{pg_port}:5432"
    environment:
      POSTGRES_PASSWORD: {db_root_password}
      POSTGRES_USER: {db_user}
      POSTGRES_DB: {db_name}
    volumes:
      - {base_path}/pg_databases:/var/lib/postgresql/data
    networks:
      - account
      - mangopanel-edge

  adminer:
    image: adminer:latest
    container_name: mp-{username}-adminer
    restart: unless-stopped
    mem_limit: 256m
    labels:
      caddy: "http://{adminer_domain}"
      caddy.reverse_proxy: "{{upstreams 8080}}"
    environment:
      ADMINER_DEFAULT_SERVER: pg
    networks:
      - account
      - mangopanel-edge

  cron:
    image: alpine:3.20
    container_name: mp-{username}-cron
    restart: unless-stopped
    command: ["crond", "-f", "-l", "8"]
    mem_limit: 128m
    volumes:
      - {base_path}:/home/{username}
      - {base_path}/.runtime/stack/cron:/etc/crontabs/root:ro
    networks:
      - account

  sftp:
    image: atmoz/sftp:alpine
    container_name: mp-{username}-sftp
    restart: unless-stopped
    mem_limit: 128m
    ports:
      - "127.0.0.1:{sftp_port}:22"
    volumes:
      - {base_path}:/home/{username}
      - {base_path}/.runtime/stack/sftp_users.conf:/etc/sftp/users.conf:ro
    networks:
      - account
      - mangopanel-edge

  smtp-relay:
    image: axllent/mailpit:latest
    container_name: mp-{username}-smtp-relay
    restart: unless-stopped
    mem_limit: 128m
    ports:
      - "127.0.0.1:{smtp_port}:1025"
    labels:
      caddy: "http://{webmail_domain}"
      caddy.reverse_proxy: "{{upstreams 8025}}"
    networks:
      - account
      - mangopanel-edge

networks:
  account:
    name: mp-{username}-net
  mangopanel-edge:
    external: true

volumes:
  db-data:
    name: mp-{username}-db-data
"""
    import re
    composed = composed.format(
        project=project,
        uid=uid,
        domains_str=domains_str,
        plan_name=plan["name"],
        username=username,
        memory=memory,
        cpu_count=cpu_count,
        storage_mb=storage_mb,
        inode_limit=inode_limit,
        backup_retention_days=backup_retention_days,
        base_path=base_path,
        default_domain=default_domain,
        public_host=runtime["public_host"],
        web_port=runtime["web_port"],
        filebrowser_port=runtime["filebrowser_port"],
        phpmyadmin_port=runtime["phpmyadmin_port"],
        db_port=runtime["db_port"],
        pg_port=runtime["pg_port"],
        adminer_port=runtime["adminer_port"],
        sftp_port=runtime["sftp_port"],
        smtp_port=runtime["smtp_port"],
        mailpit_port=runtime["mailpit_port"],
        db_name=runtime["db_name"],
        db_user=runtime["db_user"],
        db_password=runtime["db_password"],
        db_root_password=runtime["db_root_password"],
        sftp_password=runtime["sftp_password"],
        filebrowser_password=runtime.get("filebrowser_password", "admin"),
        filebrowser_secret_path=runtime.get("filebrowser_secret_path", "files"),
        phpmyadmin_secret_path=runtime.get("phpmyadmin_secret_path", "db"),
        filebrowser_domain=runtime["filebrowser_url"].split("://")[1],
        phpmyadmin_domain=runtime["phpmyadmin_url"].split("://")[1],
        adminer_domain=runtime["adminer_url"].split("://")[1],
        webmail_domain=runtime["webmail_url"].split("://")[1],
    )
    # caddy-docker-proxy requires {{upstreams N}} with literal double-braces.
    # Python .format() collapses {{ to { so we restore them after formatting.
    composed = re.sub(r'\{upstreams (\d+)\}', r'{{upstreams \1}}', composed)
    return composed


def compose_cpu_limit(value):
    raw = str(value or "1").strip().lower().replace("cores", "").replace("core", "").strip()
    try:
        cpu = float(raw)
    except ValueError:
        cpu = 1.0
    if cpu <= 0:
        cpu = 1.0
    return "{:g}".format(cpu)


def stack_summary(paths):
    return {
        "compose_path": str(paths["compose"]),
        "account_json": str(paths["account_json"]),
        "services": STACK_SERVICES,
    }
