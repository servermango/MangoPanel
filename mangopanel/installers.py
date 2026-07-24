import json
import time
from pathlib import Path

class BaseInstaller:
    id = None
    name = None
    icon = None
    description = ""
    required_fields = []

    @classmethod
    def get_info(cls):
        return {
            "id": cls.id,
            "name": cls.name,
            "icon": cls.icon,
            "description": cls.description,
            "required_fields": cls.required_fields,
        }

    @classmethod
    def verify_empty_root(cls, conn, website, allow_overwrite):
        document_root = Path(website["document_root"])
        document_root.mkdir(parents=True, exist_ok=True)
        
        existing_files = list(document_root.iterdir())
        
        # Fresh MangoPanel sites contain a generated index.php placeholder.
        placeholder_index = None
        index_php = document_root / "index.php"
        if index_php.exists():
            try:
                content = index_php.read_text(encoding="utf-8")
                if content.startswith("<?php\nheader('Content-Type: text/plain');\necho \"MangoPanel dev site:"):
                    placeholder_index = index_php
            except Exception:
                pass

        blocking_files = [path for path in existing_files if path != placeholder_index]
        if blocking_files and not allow_overwrite:
            raise Exception("document_root_not_empty")
            
        if placeholder_index:
            placeholder_index.unlink()

class WordPressInstaller(BaseInstaller):
    id = "wordpress"
    name = "WordPress"
    icon = "wordpress"
    description = "Install WordPress CMS onto your site."
    required_fields = [
        {"name": "site_title", "label": "Site Title", "type": "text", "placeholder": "My WordPress Site", "default": "My WordPress Site"},
        {"name": "admin_username", "label": "Admin Username", "type": "text", "placeholder": "admin", "default": "admin"},
        {"name": "admin_email", "label": "Admin Email", "type": "email", "placeholder": "admin@example.com", "default": "admin@example.com"},
        {"name": "admin_password", "label": "Admin Password", "type": "password", "placeholder": "Minimum 8 chars", "default": ""},
    ]

    @classmethod
    def install(cls, conn, website, account, payload, install_id):
        cls.verify_empty_root(conn, website, bool(payload.get("allow_overwrite")))
        
        document_root = Path(website["document_root"])
        document_root.mkdir(parents=True, exist_ok=True)

        template_zip = Path(__file__).resolve().parent.parent / "templates" / "wordpress.zip"
        if template_zip.exists():
            import zipfile, shutil
            with zipfile.ZipFile(template_zip, "r") as zf:
                zf.extractall(document_root)
            extracted_sub = document_root / "wordpress"
            if extracted_sub.is_dir():
                for item in extracted_sub.iterdir():
                    dest = document_root / item.name
                    if dest.exists():
                        if dest.is_dir():
                            shutil.rmtree(dest)
                        else:
                            dest.unlink()
                    shutil.move(str(item), str(document_root))
                shutil.rmtree(extracted_sub, ignore_errors=True)

        wp_config = document_root / "wp-config.php"
        
        db_name = payload.get("database_name", "wordpress")
        db_user = payload.get("database_user", "wordpress")
        db_password = payload.get("database_password", "dev-db-password-change-me")
        db_host = payload.get("database_host", "db")
        site_title = payload.get("site_title", "My Site")
        admin_username = payload.get("admin_username", "admin")
        admin_email = payload.get("admin_email", "admin@example.com")
        
        config_content = f"""<?php
// MangoPanel WordPress Configuration
define('FS_METHOD', 'direct');
define('DB_NAME', '{db_name}');
define('DB_USER', '{db_user}');
define('DB_PASSWORD', '{db_password}');
define('DB_HOST', '{db_host}');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');

define('WP_SITE_TITLE', '{site_title}');
define('WP_ADMIN_USER', '{admin_username}');
define('WP_ADMIN_EMAIL', '{admin_email}');

define('AUTH_KEY', 'put your unique phrase here');
define('SECURE_AUTH_KEY', 'put your unique phrase here');
define('LOGGED_IN_KEY', 'put your unique phrase here');
define('NONCE_KEY', 'put your unique phrase here');
define('AUTH_SALT', 'put your unique phrase here');
define('SECURE_AUTH_SALT', 'put your unique phrase here');
define('LOGGED_IN_SALT', 'put your unique phrase here');
define('NONCE_SALT', 'put your unique phrase here');

$table_prefix = 'wp_';
define('WP_DEBUG', true);

if ( !defined('ABSPATH') ) {{
    define('ABSPATH', dirname(__FILE__) . '/');
}}

require_once(ABSPATH . 'wp-settings.php');
?>"""
        wp_config.write_text(config_content, encoding="utf-8")

        index_php_file = document_root / "index.php"
        if not index_php_file.exists():
            index_php_file.write_text(
                "<?php\n"
                "define('WP_USE_THEMES', true);\n"
                "require __DIR__ . '/wp-blog-header.php';\n",
                encoding="utf-8"
            )

        htaccess = document_root / ".htaccess"
        htaccess.write_text(
            "# BEGIN WordPress\n"
            "<IfModule mod_rewrite.c>\n"
            "RewriteEngine On\n"
            "RewriteBase /\n"
            "RewriteRule ^index\\.php$ - [L]\n"
            "RewriteCond %{REQUEST_FILENAME} !-f\n"
            "RewriteCond %{REQUEST_FILENAME} !-d\n"
            "RewriteRule . /index.php [L]\n"
            "</IfModule>\n"
            "# END WordPress\n",
            encoding="utf-8"
        )

        wp_meta = document_root / ".wordpress-install"
        wp_meta.write_text(
            json.dumps({
                "install_id": install_id,
                "website_id": website["id"],
                "site_title": site_title,
                "admin_username": admin_username,
                "admin_email": admin_email,
                "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }),
            encoding="utf-8"
        )

        try:
            mu_dir = document_root / "wp-content" / "mu-plugins"
            mu_dir.mkdir(parents=True, exist_ok=True)
            (mu_dir / "mangopanel-compat.php").write_text(
                "<?php\n// MangoPanel Compatibility Plugin\nadd_filter('wp_signature_hosts', '__return_empty_array', 999);\n",
                encoding="utf-8"
            )
        except Exception:
            pass

        import os, subprocess
        uid = 5000 + int(account["id"])
        gid = 5000 + int(account["id"])
        if uid and gid:
            try:
                subprocess.run(["chown", "-R", f"{uid}:{gid}", str(document_root)], check=False)
                subprocess.run(["chmod", "-R", "a+rwX", str(document_root)], check=False)
            except Exception:
                pass
            for root_dir, dirs, files in os.walk(str(document_root)):
                for d in dirs:
                    try:
                        os.chown(os.path.join(root_dir, d), uid, gid)
                        os.chmod(os.path.join(root_dir, d), 0o777)
                    except Exception:
                        pass
                for f in files:
                    try:
                        filepath = os.path.join(root_dir, f)
                        os.chown(filepath, uid, gid)
                        st_mode = os.stat(filepath).st_mode
                        if st_mode & 0o111:
                            os.chmod(filepath, 0o777)
                        else:
                            os.chmod(filepath, 0o666)
                    except Exception:
                        pass

        conn.execute(
            "UPDATE wordpress_installs SET status = 'installed', installed_at = CURRENT_TIMESTAMP WHERE id = ?",
            (install_id,)
        )

class JoomlaInstaller(BaseInstaller):
    id = "joomla"
    name = "Joomla"
    icon = "network"
    description = "Install Joomla CMS onto your site."
    required_fields = [
        {"name": "site_title", "label": "Site Name", "type": "text", "placeholder": "My Joomla Site", "default": "My Joomla Site"},
        {"name": "admin_username", "label": "Admin Username", "type": "text", "placeholder": "admin", "default": "admin"},
        {"name": "admin_email", "label": "Admin Email", "type": "email", "placeholder": "admin@example.com", "default": "admin@example.com"},
        {"name": "admin_password", "label": "Admin Password", "type": "password", "placeholder": "Minimum 8 chars", "default": ""},
    ]

    @classmethod
    def install(cls, conn, website, account, payload, install_id):
        cls.verify_empty_root(conn, website, bool(payload.get("allow_overwrite")))
        
        document_root = Path(website["document_root"])
        config_file = document_root / "configuration.php"
        
        db_name = payload.get("database_name", "joomla")
        db_user = payload.get("database_user", "joomla")
        db_password = payload.get("database_password", "dev-db-password-change-me")
        db_host = payload.get("database_host", "db")
        site_title = payload.get("site_title", "My Site")
        admin_username = payload.get("admin_username", "admin")
        admin_email = payload.get("admin_email", "admin@example.com")

        config_content = f"""<?php
// MangoPanel Joomla Configuration
class JConfig {{
    public $dbtype = 'mysqli';
    public $host = '{db_host}';
    public $user = '{db_user}';
    public $password = '{db_password}';
    public $db = '{db_name}';
    public $dbprefix = 'jos_';
    public $sitename = '{site_title}';
    public $mailfrom = '{admin_email}';
}}
?>"""
        config_file.write_text(config_content, encoding="utf-8")

        index_php_file = document_root / "index.php"
        index_php_file.write_text(
            "<?php\n"
            "header('Content-Type: text/html; charset=utf-8');\n"
            "?>\n"
            "<!doctype html>\n"
            "<html lang=\"en\"><head><meta charset=\"utf-8\"><title>{}</title></head>\n"
            "<body style=\"font-family: system-ui, sans-serif; max-width: 760px; margin: 4rem auto; line-height: 1.5;\">\n"
            "<h1>{}</h1>\n"
            "<p>Joomla development install is ready for this MangoPanel site.</p>\n"
            "<p><strong>Admin user:</strong> {}</p>\n"
            "</body></html>\n".format(
                site_title.replace("<", "&lt;").replace(">", "&gt;"),
                site_title.replace("<", "&lt;").replace(">", "&gt;"),
                admin_username.replace("<", "&lt;").replace(">", "&gt;"),
            ),
            encoding="utf-8"
        )

        joomla_meta = document_root / ".joomla-install"
        joomla_meta.write_text(
            json.dumps({
                "install_id": install_id,
                "website_id": website["id"],
                "site_title": site_title,
                "admin_username": admin_username,
                "admin_email": admin_email,
                "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }),
            encoding="utf-8"
        )

class PhpBBInstaller(BaseInstaller):
    id = "phpbb"
    name = "phpBB"
    icon = "activity"
    description = "Install phpBB Forum software onto your site."
    required_fields = [
        {"name": "site_title", "label": "Forum Name", "type": "text", "placeholder": "My phpBB Forum", "default": "My phpBB Forum"},
        {"name": "admin_username", "label": "Admin Username", "type": "text", "placeholder": "admin", "default": "admin"},
        {"name": "admin_email", "label": "Admin Email", "type": "email", "placeholder": "admin@example.com", "default": "admin@example.com"},
        {"name": "admin_password", "label": "Admin Password", "type": "password", "placeholder": "Minimum 8 chars", "default": ""},
    ]

    @classmethod
    def install(cls, conn, website, account, payload, install_id):
        cls.verify_empty_root(conn, website, bool(payload.get("allow_overwrite")))
        
        document_root = Path(website["document_root"])
        config_file = document_root / "config.php"
        
        db_name = payload.get("database_name", "phpbb")
        db_user = payload.get("database_user", "phpbb")
        db_password = payload.get("database_password", "dev-db-password-change-me")
        db_host = payload.get("database_host", "db")
        site_title = payload.get("site_title", "My Forum")
        admin_username = payload.get("admin_username", "admin")
        admin_email = payload.get("admin_email", "admin@example.com")

        config_content = f"""<?php
// MangoPanel phpBB Configuration
$dbms = 'mysqli';
$dbhost = '{db_host}';
$dbport = '';
$dbname = '{db_name}';
$dbuser = '{db_user}';
$dbpasswd = '{db_password}';
$table_prefix = 'phpbb_';
define('PHPBB_INSTALLED', true);
?>"""
        config_file.write_text(config_content, encoding="utf-8")

        index_php_file = document_root / "index.php"
        index_php_file.write_text(
            "<?php\n"
            "header('Content-Type: text/html; charset=utf-8');\n"
            "?>\n"
            "<!doctype html>\n"
            "<html lang=\"en\"><head><meta charset=\"utf-8\"><title>{}</title></head>\n"
            "<body style=\"font-family: system-ui, sans-serif; max-width: 760px; margin: 4rem auto; line-height: 1.5;\">\n"
            "<h1>{}</h1>\n"
            "<p>phpBB development install is ready for this MangoPanel site.</p>\n"
            "<p><strong>Admin user:</strong> {}</p>\n"
            "</body></html>\n".format(
                site_title.replace("<", "&lt;").replace(">", "&gt;"),
                site_title.replace("<", "&lt;").replace(">", "&gt;"),
                admin_username.replace("<", "&lt;").replace(">", "&gt;"),
            ),
            encoding="utf-8"
        )

        phpbb_meta = document_root / ".phpbb-install"
        phpbb_meta.write_text(
            json.dumps({
                "install_id": install_id,
                "website_id": website["id"],
                "site_title": site_title,
                "admin_username": admin_username,
                "admin_email": admin_email,
                "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }),
            encoding="utf-8"
        )

class DrupalInstaller(BaseInstaller):
    id = "drupal"
    name = "Drupal"
    icon = "wrench"
    description = "Install Drupal CMS onto your site."
    required_fields = [
        {"name": "site_title", "label": "Site Name", "type": "text", "placeholder": "My Drupal Site", "default": "My Drupal Site"},
        {"name": "admin_username", "label": "Admin Username", "type": "text", "placeholder": "admin", "default": "admin"},
        {"name": "admin_email", "label": "Admin Email", "type": "email", "placeholder": "admin@example.com", "default": "admin@example.com"},
        {"name": "admin_password", "label": "Admin Password", "type": "password", "placeholder": "Minimum 8 chars", "default": ""},
    ]

    @classmethod
    def install(cls, conn, website, account, payload, install_id):
        cls.verify_empty_root(conn, website, bool(payload.get("allow_overwrite")))
        
        document_root = Path(website["document_root"])
        config_dir = document_root / "sites" / "default"
        config_dir.mkdir(parents=True, exist_ok=True)
        config_file = config_dir / "settings.php"
        
        db_name = payload.get("database_name", "drupal")
        db_user = payload.get("database_user", "drupal")
        db_password = payload.get("database_password", "dev-db-password-change-me")
        db_host = payload.get("database_host", "db")
        site_title = payload.get("site_title", "My Site")
        admin_username = payload.get("admin_username", "admin")
        admin_email = payload.get("admin_email", "admin@example.com")

        config_content = f"""<?php
// MangoPanel Drupal Configuration
$databases['default']['default'] = array (
  'database' => '{db_name}',
  'username' => '{db_user}',
  'password' => '{db_password}',
  'prefix' => '',
  'host' => '{db_host}',
  'port' => '3306',
  'namespace' => 'Drupal\\\\Core\\\\Database\\\\Driver\\\\mysql',
  'driver' => 'mysql',
);
$settings['hash_salt'] = 'dev-hash-salt-only-change-in-prod';
?>"""
        config_file.write_text(config_content, encoding="utf-8")

        index_php_file = document_root / "index.php"
        index_php_file.write_text(
            "<?php\n"
            "header('Content-Type: text/html; charset=utf-8');\n"
            "?>\n"
            "<!doctype html>\n"
            "<html lang=\"en\"><head><meta charset=\"utf-8\"><title>{}</title></head>\n"
            "<body style=\"font-family: system-ui, sans-serif; max-width: 760px; margin: 4rem auto; line-height: 1.5;\">\n"
            "<h1>{}</h1>\n"
            "<p>Drupal development install is ready for this MangoPanel site.</p>\n"
            "<p><strong>Admin user:</strong> {}</p>\n"
            "</body></html>\n".format(
                site_title.replace("<", "&lt;").replace(">", "&gt;"),
                site_title.replace("<", "&lt;").replace(">", "&gt;"),
                admin_username.replace("<", "&lt;").replace(">", "&gt;"),
            ),
            encoding="utf-8"
        )

        drupal_meta = document_root / ".drupal-install"
        drupal_meta.write_text(
            json.dumps({
                "install_id": install_id,
                "website_id": website["id"],
                "site_title": site_title,
                "admin_username": admin_username,
                "admin_email": admin_email,
                "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }),
            encoding="utf-8"
        )

INSTALLERS = {
    "wordpress": WordPressInstaller,
    "joomla": JoomlaInstaller,
    "phpbb": PhpBBInstaller,
    "drupal": DrupalInstaller,
}
