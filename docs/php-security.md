# PHP runtime security maintenance

Administrators with `hosting.manage` can use **Update PHP security** on a hosting account. The asynchronous `update_account_php_security` agent job updates the account's installed LSAPI packages within their existing PHP branches, builds official pinned source backports for installed PHP 7.4/8.0/8.1 cores, recycles only its web container, replaces the separate WebAdmin PHP 5.6 handler with a launcher for patched PHP 8.2, and updates its running phpMyAdmin, Adminer and SnappyMail services. Databases, Redis, website content, mail storage and account records are retained.

The job archives all LSAPI runtimes (including extensions and INIs) and package metadata under `/root/mangopanel-php-security/`; auxiliary service Compose files and rollback images are retained under `/root/mangopanel-php-security-tools/`. These paths contain private configuration and must remain root-only. Restoring a pre-patch PHP runtime restores the vulnerability; use rollback only to recover service while arranging a fixed build.

Fixed upstream baselines are PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12. Older vendor-supported releases can carry backports; check the vendor's exact package/build rather than comparing only the PHP version. Legacy LSAPI core builds use the immutable commits in `mangopanel/php_legacy.py`, linked from PHP's official October 21 advisory. Builds run two compiler jobs at low CPU priority. Existing compatible extensions and INI customizations remain in place.

`session.upload_progress.enabled=0` is installed in startup INIs, generated per-vhost admin settings, and auxiliary service INI mounts, following PHP's October 23 follow-up. New account Dockerfiles build legacy cores only for PHP branches actually selected by their sites, so modern-only accounts do not compile unused runtimes. They fail if supported LSAPI branches are below the fixed baselines. Rebuilds retain pinned fixed tool images.

Check the **web SAPI** after maintenance: the panel's `8.3` selection and a host CLI executable do not establish the exact version running a site. Detached LSAPI workers must also be recycled. Test the site's login/upload flows as appropriate; disabling upload progress does not disable file uploads but removes PHP's built-in session progress tracking.

Official advisory: https://www.php.net/archive/2026.php
Follow-up: https://www.php.net/
