from __future__ import annotations

from flask import Flask, Response

SCANNER_DECOY_PATHS: set[str] = {
    "/.env",
    "/.env.backup",
    "/.git/config",
    "/.git/HEAD",
    "/.aws/credentials",
    "/wp-login.php",
    "/wp-admin/",
    "/xmlrpc.php",
    "/phpmyadmin/",
    "/phpmyadmin/index.php",
    "/server-status",
    "/actuator/env",
    "/actuator/health",
    "/admin/config.json",
    "/config.json",
    "/backup.sql",
    "/.ssh/id_rsa",
}

FAKE_ENV = (
    "APP_ENV=production\n"
    "APP_DEBUG=false\n"
    "APP_KEY=base64:Qk5yV29WdllWVVpqaGdNTXlUTDNFVXVRTmxjRm5HYno=\n"
    "DB_CONNECTION=postgres\n"
    "DB_HOST=payflow-db-primary.internal\n"
    "DB_PORT=5432\n"
    "DB_DATABASE=payflow_prod\n"
    "DB_USERNAME=svc-payments\n"
    "DB_PASSWORD=P@yments2024!\n"
    "STRIPE_KEY=pk_live_51Hxxx0ExampleDecoyKey0xxxZ\n"
    "STRIPE_SECRET=sk_live_51Hxxx0ExampleDecoyKey0xxxZ\n"
    "VAULT_TOKEN=s.decoy.honeypot.token.ignore\n"
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
)

FAKE_GIT_CONFIG = (
    "[core]\n"
    "    repositoryformatversion = 0\n"
    "    filemode = true\n"
    "    bare = false\n"
    "    logallrefupdates = true\n"
    "[remote \"origin\"]\n"
    "    url = git@github.com:payflow-internal/payments-core.git\n"
    "    fetch = +refs/heads/*:refs/remotes/origin/*\n"
    "[branch \"main\"]\n"
    "    remote = origin\n"
    "    merge = refs/heads/main\n"
)

FAKE_AWS_CREDENTIALS = (
    "[default]\n"
    "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
    "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    "region = us-east-1\n"
)

FAKE_WP_LOGIN = """<!DOCTYPE html>
<html><head><title>Log In &lsaquo; PayFlow Ops Blog &mdash; WordPress</title></head>
<body class="login login-action-login wp-core-ui">
<div id="login">
  <h1><a href="/">PayFlow Ops Blog</a></h1>
  <form name="loginform" id="loginform" action="/wp-login.php" method="post">
    <p><label>Username or Email Address<br><input type="text" name="log" class="input" value="" size="20"></label></p>
    <p><label>Password<br><input type="password" name="pwd" class="input" value="" size="20"></label></p>
    <p class="submit"><input type="submit" name="wp-submit" class="button button-primary button-large" value="Log In"></p>
  </form>
</div>
</body></html>"""

FAKE_PHPMYADMIN = """<!DOCTYPE html>
<html><head><title>phpMyAdmin 5.2.1</title></head>
<body>
<div id="page_content">
  <h1>Welcome to phpMyAdmin</h1>
  <form method="post" action="index.php" name="login_form" class="disableAjax login hide js-show">
    <fieldset>
      <legend>Log in</legend>
      <input type="text" name="pma_username" placeholder="Username" value="">
      <input type="password" name="pma_password" placeholder="Password">
      <input type="hidden" name="server" value="1">
      <input type="submit" value="Go">
    </fieldset>
  </form>
  <div class="versioninfo">Server: payflow-db-primary.internal via TCP/IP</div>
</div>
</body></html>"""

FAKE_SERVER_STATUS = """<html><head><title>Apache Status</title></head>
<body><h1>Apache Server Status for payflow-edge-01.internal</h1>
<dl>
<dt>Server Version: Apache/2.4.57 (Ubuntu)</dt>
<dt>Server MPM: event</dt>
<dt>Server Built: 2024-01-15T00:00:00</dt>
<dt>Current Time: runtime</dt>
<dt>Parent Server Config. Generation: 1</dt>
<dt>Total accesses: 48213 - Total Traffic: 512 MB</dt>
<dt>CPU Usage: u.48 s.12 cu0 cs0</dt>
</dl><pre>
Scoreboard Key:
"_" Waiting for Connection, "S" Starting up, "R" Reading Request,
"W" Sending Reply, "K" Keepalive (read), "D" DNS Lookup
</pre></body></html>"""

FAKE_ACTUATOR_ENV = """{
  "activeProfiles": ["prod"],
  "propertySources": [
    {"name": "systemEnvironment", "properties": {
        "DB_URL": {"value": "jdbc:postgresql://payflow-db-primary.internal:5432/payflow_prod"},
        "DB_USER": {"value": "svc-payments"},
        "DB_PASS": {"value": "P@yments2024!"},
        "VAULT_TOKEN": {"value": "s.decoy.honeypot.token.ignore"}
    }}
  ]
}"""

FAKE_CONFIG_JSON = """{
  "service": "payflow-admin",
  "version": "3.4.1",
  "datastore": {"host": "payflow-db-primary.internal", "user": "db_admin", "password": "CardVault#2024"},
  "vault": {"endpoint": "https://vault.internal:8200", "token": "s.decoy.honeypot.token.ignore"},
  "feature_flags": {"refund_override": true, "vault_export": true}
}"""

FAKE_BACKUP_SQL = """-- PayFlow production dump (decoy)
-- MySQL dump 10.13  Distrib 8.0.36
DROP TABLE IF EXISTS `payment_records`;
CREATE TABLE `payment_records` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `record_id` VARCHAR(32),
  `cardholder` VARCHAR(128),
  `last4` CHAR(4),
  PRIMARY KEY (`id`)
);
INSERT INTO `payment_records` VALUES (1,'pay_1001','Elena M.','4242');
"""

ROBOTS_TXT = """User-agent: *
Disallow: /admin/
Disallow: /portal/admin
Disallow: /api/cards/
Disallow: /api/transactions/
Disallow: /vault/
Disallow: /backup.sql
Disallow: /.env
Disallow: /.git/
"""

SITEMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://payflow.local/</loc></url>
  <url><loc>http://payflow.local/auth/login</loc></url>
  <url><loc>http://payflow.local/portal/admin</loc></url>
  <url><loc>http://payflow.local/api/payments/search</loc></url>
</urlset>
"""


def register_scanner_decoys(app: Flask) -> None:
    @app.get("/.env")
    def env_file() -> Response:
        return Response(FAKE_ENV, mimetype="text/plain")

    @app.get("/.env.backup")
    def env_backup() -> Response:
        return Response(FAKE_ENV, mimetype="text/plain")

    @app.get("/.git/config")
    def git_config() -> Response:
        return Response(FAKE_GIT_CONFIG, mimetype="text/plain")

    @app.get("/.git/HEAD")
    def git_head() -> Response:
        return Response("ref: refs/heads/main\n", mimetype="text/plain")

    @app.get("/.aws/credentials")
    def aws_credentials() -> Response:
        return Response(FAKE_AWS_CREDENTIALS, mimetype="text/plain")

    @app.get("/.ssh/id_rsa")
    def ssh_key() -> Response:
        return Response("-----BEGIN OPENSSH PRIVATE KEY-----\nDECOYKEYMATERIALDONOTUSE\n-----END OPENSSH PRIVATE KEY-----\n", mimetype="text/plain")

    @app.get("/wp-login.php")
    def wp_login() -> Response:
        return Response(FAKE_WP_LOGIN, mimetype="text/html")

    @app.get("/wp-admin/")
    def wp_admin() -> Response:
        return Response(FAKE_WP_LOGIN, mimetype="text/html")

    @app.route("/xmlrpc.php", methods=["GET", "POST"])
    def xmlrpc() -> Response:
        return Response("<?xml version=\"1.0\"?><methodResponse><params><param><value><string>XML-RPC server accepts POST requests only.</string></value></param></params></methodResponse>", mimetype="text/xml")

    @app.get("/phpmyadmin/")
    def phpmyadmin_root() -> Response:
        return Response(FAKE_PHPMYADMIN, mimetype="text/html")

    @app.get("/phpmyadmin/index.php")
    def phpmyadmin_index() -> Response:
        return Response(FAKE_PHPMYADMIN, mimetype="text/html")

    @app.get("/server-status")
    def server_status() -> Response:
        return Response(FAKE_SERVER_STATUS, mimetype="text/html")

    @app.get("/actuator/env")
    def actuator_env() -> Response:
        return Response(FAKE_ACTUATOR_ENV, mimetype="application/json")

    @app.get("/actuator/health")
    def actuator_health() -> Response:
        return Response('{"status":"UP","components":{"db":{"status":"UP"},"vault":{"status":"UP"}}}', mimetype="application/json")

    @app.get("/admin/config.json")
    def admin_config() -> Response:
        return Response(FAKE_CONFIG_JSON, mimetype="application/json")

    @app.get("/config.json")
    def config_json() -> Response:
        return Response(FAKE_CONFIG_JSON, mimetype="application/json")

    @app.get("/backup.sql")
    def backup_sql() -> Response:
        return Response(FAKE_BACKUP_SQL, mimetype="application/sql")

    @app.get("/robots.txt")
    def robots_txt() -> Response:
        return Response(ROBOTS_TXT, mimetype="text/plain")

    @app.get("/sitemap.xml")
    def sitemap_xml() -> Response:
        return Response(SITEMAP_XML, mimetype="application/xml")
