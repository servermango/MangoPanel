"""Build legacy LSAPI cores from PHP's pinned official PHP2Shell backports."""
SOURCES = {
    '74': ('litespeedtech/openlitespeed:1.7.14-lsphp74', '712e60f9edfd03f0960fc4fc3c2c375f42b90aa2'),
    '80': ('litespeedtech/openlitespeed:1.7.14-lsphp80', '82f8f31b16a035c1b67cc253e79f7cc288f4cc20'),
    '81': ('litespeedtech/openlitespeed:1.8.4-lsphp81', '1d7dec178a094e6e75b229ce22754045f8c6070a'),
}


def legacy_security_stages():
    stages = []
    for version, (base, commit) in SOURCES.items():
        dotted = version[0] + '.' + version[1]
        api = {'74': '20190902', '80': '20200930', '81': '20210902'}[version]
        legacy_flags = '--with-enchant --with-xmlrpc' if version == '74' else '--with-enchant'
        legacy_packages = 'libenchant-2-dev' if version == '81' else 'libenchant-dev'
        json_flag = '--enable-json=shared' if version == '74' else ''
        stages.append(f'''FROM {base} AS php{version}_security_build
USER root
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential autoconf bison re2c pkg-config curl ca-certificates libxml2-dev libssl-dev libsqlite3-dev libonig-dev libzip-dev libbz2-dev libcurl4-openssl-dev libjpeg-dev libpng-dev libwebp-dev libfreetype6-dev libxslt1-dev libgmp-dev libsodium-dev libargon2-dev libedit-dev {legacy_packages}
WORKDIR /src
ADD https://codeload.github.com/php/php-src/tar.gz/{commit} /src/source.tgz
RUN tar -xzf source.tgz --strip-components=1 && ./buildconf --force
RUN ./configure --prefix=/usr/local/lsws/lsphp{version} --enable-cli --disable-cgi --disable-phpdbg --enable-litespeed --with-config-file-path=/usr/local/lsws/lsphp{version}/etc/php/{dotted}/litespeed --with-config-file-scan-dir=/usr/local/lsws/lsphp{version}/etc/php/{dotted}/mods-available --with-openssl --with-zlib --with-bz2 --with-curl=shared --enable-bcmath --enable-calendar --enable-exif --enable-ftp --with-gettext --with-gmp --enable-mbstring --enable-mysqlnd --with-mysqli=shared,mysqlnd --with-pdo-mysql=shared,mysqlnd --enable-pcntl --enable-sysvmsg --enable-sysvsem --enable-sysvshm {legacy_flags} --enable-sockets --enable-soap --with-xsl --with-zip --with-sodium --with-password-argon2 --with-libedit --enable-gd --with-jpeg --with-webp --with-freetype {json_flag} --enable-opcache
RUN nice -n 19 make -j2 && sapi/cli/php -n -v && sapi/litespeed/php -n -v
FROM {base} AS php{version}_security
COPY --from=php{version}_security_build /src/sapi/cli/php /usr/local/lsws/lsphp{version}/bin/php
COPY --from=php{version}_security_build /src/sapi/litespeed/php /usr/local/lsws/lsphp{version}/bin/lsphp
RUN printf 'extension_dir=/usr/local/lsws/lsphp{version}/lib/php/{api}\\n' > /usr/local/lsws/lsphp{version}/etc/php/{dotted}/mods-available/zz-mangopanel-extension-dir.ini
RUN printf 'PHP upstream backport {commit} CVE-2026-109618 CVE-2026-109619\\n' > /usr/local/lsws/lsphp{version}/PHP2SHELL-PATCHED
''')
    return '\n'.join(stages)
