"""Scoped PHP security maintenance. Never recreates databases or changes PHP branches."""
import json
import re
import subprocess
import time
from pathlib import Path

MINIMUM_PHP = {'8.2': (8, 2, 35), '8.3': (8, 3, 36), '8.4': (8, 4, 27), '8.5': (8, 5, 12)}


def is_patched(version):
    match = re.search(r'(\d+)\.(\d+)\.(\d+)', version)
    if not match:
        return False
    parts = tuple(map(int, match.groups()))
    minimum = MINIMUM_PHP.get('.'.join(map(str, parts[:2])))
    return minimum is not None and parts >= minimum


def update_account_php(account, backup_root=Path('/root/mangopanel-php-security')):
    account = dict(account)
    username = str(account['username'])
    if not re.fullmatch(r'[a-zA-Z0-9_]+', username):
        raise ValueError('invalid_account_username')
    container = f'mp-{username}-web'
    backup = Path(backup_root) / (time.strftime('%Y%m%d-%H%M%S', time.gmtime()) + '-' + username)
    backup.mkdir(parents=True, mode=0o700, exist_ok=False)

    def command(args, timeout=600):
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        with (backup / 'commands.log').open('a') as log:
            log.write(json.dumps(args) + '\n' + result.stdout + result.stderr + '\n')
        (backup / 'commands.log').chmod(0o600)
        if result.returncode:
            raise RuntimeError('php_security_update_failed; see ' + str(backup))
        return result.stdout

    # Archive every PHP runtime/extension/INI plus package metadata, excluding
    # unrelated web logs and bind-mounted customer data. No container pause.
    archive = backup / 'php-runtime-before.tar'
    with archive.open('wb') as output:
        archive.chmod(0o600)
        result = subprocess.run(['docker', 'exec', container, 'sh', '-c',
            'cd / && tar -cf - usr/local/lsws/lsphp* var/lib/dpkg/status etc/apt'],
            stdout=output, stderr=subprocess.PIPE, timeout=600)
    if result.returncode:
        (backup / 'backup-error.log').write_bytes(result.stderr)
        (backup / 'backup-error.log').chmod(0o600)
        raise RuntimeError('php_runtime_backup_failed; see ' + str(backup))
    command(['tar', '-tf', str(archive)])
    (backup / 'base-image.txt').write_text(command(['docker', 'inspect', '--format', '{{.Image}}', container]))
    script = r'''set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=25 update
packages=$(dpkg-query -W -f='${db:Status-Status} ${Package}\n' 'lsphp*' 2>/dev/null | awk '$1 == "installed" {print $2}')
[ -n "$packages" ]
apt-get install -y --only-upgrade $packages
for dir in /usr/local/lsws/lsphp*/etc/php/*/mods-available; do
  [ -d "$dir" ] || continue
  printf '; PHP security guidance 2026-10-23\nsession.upload_progress.enabled=0\n' > "$dir/zz-mangopanel-security.ini"
done
for php in /usr/local/lsws/lsphp8[2345]/bin/php; do
  [ ! -x "$php" ] || "$php" -r '$v=PHP_VERSION; $m=["8.2"=>"8.2.35","8.3"=>"8.3.36","8.4"=>"8.4.27","8.5"=>"8.5.12"]; $b=PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION; if(!isset($m[$b]) || version_compare($v,$m[$b],"<"))exit(1); echo $v."\n";'
done
'''
    command(['docker', 'exec', container, 'bash', '-c', script], timeout=1200)
    legacy = update_legacy_php(container, backup, command)
    webadmin = update_admin_php(container, backup, command)
    # Restart only this web container, clearing detached workers running old code.
    command(['docker', 'restart', '-t', '30', container], timeout=90)
    tools = update_account_tools(account) if account.get('base_path') else None
    return {'account_id': account['id'], 'container': container, 'backup': str(backup), 'rollback_archive': str(archive), 'status': 'updated', 'php_branch_preserved': True, 'tools': tools, 'legacy_backports': legacy, 'webadmin': webadmin}


TOOL_IMAGES = {
    'phpmyadmin': 'phpmyadmin:latest@sha256:62a50b1419fe55b9b4c3cd6f5aed03a18f8f5b4a236f24735d76400bea75a5ff',
    'adminer': 'adminer:latest@sha256:251295c1cd51d3889f1c42ffa4864b24eeab51f0caf395cfe5bf4726c5ec9a2a',
    'mailproxy': 'djmaze/snappymail:latest@sha256:cc053169c76e27d54c3533b002ec9987786ca50bf9265ae318b44d8699f60ec0',
}


def secure_tool_compose(text, ini_path):
    """Edit only PHP tool services; retain labels, networks, environment and volumes."""
    mount = f'      - {ini_path}:/usr/local/etc/php/conf.d/zz-mangopanel-security.ini:ro\n'
    for service, image in TOOL_IMAGES.items():
        pattern = rf'(?ms)^  {service}:\n.*?(?=^  [a-zA-Z][\w-]*:\n|^\S|\Z)'
        def replace(match):
            block = match.group(0)
            block = re.sub(r'^    image:.*$', '    image: ' + image, block, count=1, flags=re.M)
            if '/zz-mangopanel-security.ini:ro' not in block:
                if '    volumes:\n' in block:
                    block = block.replace('    volumes:\n', '    volumes:\n' + mount, 1)
                else:
                    block = block.replace('    networks:\n', '    volumes:\n' + mount + '    networks:\n', 1)
            return block
        text = re.sub(pattern, replace, text)
    return text


def update_account_tools(account, backup_root=Path('/root/mangopanel-php-security-tools')):
    """Update only running PHP tools, keeping their persistent account data."""
    import shutil
    account = dict(account)
    username = str(account['username'])
    if not re.fullmatch(r'[a-zA-Z0-9_]+', username):
        raise ValueError('invalid_account_username')
    stack = Path(account['base_path']) / '.runtime/stack'
    compose = stack / 'docker-compose.yml'
    original = compose.read_text()
    ini = stack / 'php-security.ini'
    updated = secure_tool_compose(original, ini)
    backup = Path(backup_root) / (time.strftime('%Y%m%d-%H%M%S', time.gmtime()) + '-' + username)
    backup.mkdir(parents=True, mode=0o700, exist_ok=False)
    shutil.copy2(compose, backup / 'docker-compose.yml')
    (backup / 'docker-compose.yml').chmod(0o600)
    def command(args, timeout=600):
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        log = backup / 'commands.log'
        with log.open('a') as f:
            f.write(json.dumps(args) + '\n' + result.stdout + result.stderr + '\n')
        log.chmod(0o600)
        if result.returncode:
            raise RuntimeError('php_tool_security_update_failed; see ' + str(backup))
        return result.stdout
    running = command(['docker', 'ps', '--format', '{{.Names}}']).splitlines()
    services = [s for s in TOOL_IMAGES if f'mp-{username}-{s}' in running]
    for service in services:
        image = TOOL_IMAGES[service]
        command(['docker', 'pull', image])
        version = command(['docker', 'run', '--rm', '--entrypoint', 'php', image, '-r', 'echo PHP_VERSION;'])
        if not is_patched(version):
            raise RuntimeError('unpatched_tool_image: ' + service)
        command(['docker', 'commit', '--pause=false', f'mp-{username}-{service}', 'mangopanel-tool-rollback:' + backup.name + '-' + service])
    ini.write_text('session.upload_progress.enabled=0\n')
    ini.chmod(0o644)
    compose.write_text(updated)
    try:
        command(['docker', 'compose', '-f', str(compose), 'config', '--quiet'])
    except Exception:
        compose.write_text(original)
        raise
    for service in services:
        command(['docker', 'compose', '-f', str(compose), 'up', '-d', '--no-deps', service])
        value = command(['docker', 'exec', f'mp-{username}-{service}', 'php', '-r', 'echo PHP_VERSION." ".ini_get("session.upload_progress.enabled");'])
        if not is_patched(value) or value.strip().split()[-1] != '0':
            raise RuntimeError('php_tool_runtime_verification_failed: ' + service)
    return {'account_id': account['id'], 'services': services, 'backup': str(backup), 'status': 'updated'}


def update_legacy_php(container, backup, command, versions=None):
    """Keep legacy applications on their branch using official pinned source backports."""
    from .php_legacy import SOURCES, legacy_security_stages
    installed = command(['docker', 'exec', container, 'sh', '-c', 'for v in 74 80 81; do [ ! -x /usr/local/lsws/lsphp$v/bin/lsphp ] || echo $v; done']).splitlines()
    updated = []
    for version in installed:
        if versions is not None and version not in versions:
            continue
        if version not in SOURCES:
            raise ValueError('unexpected_legacy_version')
        current = command(['docker', 'exec', container, 'sh', '-c', 'test ! -f /usr/local/lsws/lsphp' + version + '/PHP2SHELL-PATCHED || cat /usr/local/lsws/lsphp' + version + '/PHP2SHELL-PATCHED'])
        if SOURCES[version][1] in current:
            continue
        image = f'mangopanel-lsphp{version}:php2shell-20261025'
        if not command(['docker', 'images', '-q', image]).strip():
            dockerfile = backup / 'legacy.Dockerfile'
            dockerfile.write_text(legacy_security_stages())
            context = backup / 'build-context'
            context.mkdir(exist_ok=True)
            command(['docker', 'build', '-f', str(dockerfile), '--target', f'php{version}_security', '-t', image, str(context)], timeout=2400)
        prefix = f'/usr/local/lsws/lsphp{version}'
        before_extensions = json.loads(command(['docker', 'exec', '-e', 'LD_LIBRARY_PATH=/opt/mangopanel-legacy-libs', container, prefix + '/bin/php', '-r', 'echo json_encode(get_loaded_extensions());']))
        marker = command(['docker', 'run', '--rm', '--entrypoint', 'cat', image, prefix + '/PHP2SHELL-PATCHED'])
        if SOURCES[version][1] not in marker:
            raise RuntimeError('legacy_backport_provenance_failed')
        staged = backup / ('lsphp' + version)
        staged.mkdir()
        scratch = command(['docker', 'create', image, '/bin/true']).strip()
        try:
            compatibility = command(['docker', 'run', '--rm', '--entrypoint', 'sh', image, '-c', 'test ! -f ' + prefix + '/PHP2SHELL-COMPATIBILITY || cat ' + prefix + '/PHP2SHELL-COMPATIBILITY']).split()
            api = {'74': '20190902', '80': '20200930', '81': '20210902'}[version]
            for name in compatibility:
                if name not in {'sysvmsg', 'sysvsem', 'sysvshm', 'xmlrpc', 'enchant'}:
                    raise RuntimeError('invalid_compatibility_module')
                command(['docker', 'cp', scratch + ':' + prefix + '/lib/php/' + api + '/' + name + '.so', str(staged / (name + '.so'))])
                command(['docker', 'cp', str(staged / (name + '.so')), container + ':' + prefix + '/lib/php/' + api + '/' + name + '.so'])
            if compatibility:
                source = prefix + '/etc/php/' + version[0] + '.' + version[1] + '/mods-available/zz-mangopanel-compatibility.ini'
                command(['docker', 'cp', scratch + ':' + source, str(staged / 'zz-mangopanel-compatibility.ini')])
                command(['docker', 'cp', str(staged / 'zz-mangopanel-compatibility.ini'), container + ':' + source + '.security-new'])
            for executable in ['php', 'lsphp']:
                command(['docker', 'cp', scratch + ':' + prefix + '/bin/' + executable, str(staged / executable)])
        finally:
            command(['docker', 'rm', scratch])
        # Validate each binary with the existing container libraries before activating it.
        for executable in ['php', 'lsphp']:
            destination = prefix + '/bin/' + executable
            command(['docker', 'cp', str(staged / executable), container + ':' + destination + '.security-new'])
            command(['docker', 'exec', container, 'sh', '-c', 'LD_LIBRARY_PATH=/opt/mangopanel-legacy-libs ' + destination + '.security-new -n -v'])
        api = {'74': '20190902', '80': '20200930', '81': '20210902'}[version]
        extension_dir = prefix + '/lib/php/' + api
        arguments = ['docker', 'exec', '-e', 'LD_LIBRARY_PATH=/opt/mangopanel-legacy-libs', container, prefix + '/bin/php.security-new', '-d', 'extension_dir=' + extension_dir]
        for name in compatibility:
            arguments.extend(['-d', 'extension=' + name + '.so'])
        arguments.extend(['-r', 'echo json_encode(get_loaded_extensions());'])
        after_extensions = json.loads(command(arguments))
        missing = set(before_extensions) - set(after_extensions)
        if missing:
            raise RuntimeError('legacy_extensions_would_be_lost: ' + ','.join(sorted(missing)))
        ini_path = prefix + '/etc/php/' + version[0] + '.' + version[1] + '/mods-available/zz-mangopanel-extension-dir.ini'
        command(['docker', 'exec', container, 'sh', '-c', 'echo extension_dir=' + extension_dir + ' > ' + ini_path])
        for executable in ['php', 'lsphp']:
            destination = prefix + '/bin/' + executable
            command(['docker', 'exec', container, 'mv', destination + '.security-new', destination])
        if compatibility:
            command(['docker', 'exec', container, 'mv', source + '.security-new', source])
        (staged / 'PHP2SHELL-PATCHED').write_text(marker)
        command(['docker', 'cp', str(staged / 'PHP2SHELL-PATCHED'), container + ':' + prefix + '/PHP2SHELL-PATCHED'])
        updated.append(version)
    return updated


ADMIN_PHP_LAUNCHER = '#!/bin/sh\nexec /usr/local/lsws/lsphp82/bin/lsphp -c /usr/local/lsws/admin/misc/php.ini "$@"\n'


def admin_php_dockerfile():
    """Keep WebAdmin on the same maintained PHP branch as its validated launcher."""
    import shlex
    lines = ' '.join(shlex.quote(line) for line in ADMIN_PHP_LAUNCHER.splitlines())
    return "RUN printf '%s\\n' " + lines + " > /usr/local/lsws/admin/fcgi-bin/admin_php && chmod 755 /usr/local/lsws/admin/fcgi-bin/admin_php\n"


def update_admin_php(container, backup, command):
    """Patch the separate WebAdmin PHP handler without restarting website workers."""
    target = '/usr/local/lsws/admin/fcgi-bin/admin_php'
    command(['docker', 'cp', container + ':' + target, str(backup / 'admin_php.before')])
    launcher = backup / 'admin_php.launcher'
    launcher.write_text(ADMIN_PHP_LAUNCHER)
    launcher.chmod(0o755)
    command(['docker', 'cp', str(launcher), container + ':' + target + '.security-new'])
    command(['docker', 'exec', container, 'sh', '-c', 'chmod 755 ' + target + '.security-new && mv ' + target + '.security-new ' + target])
    command(['docker', 'exec', container, 'sh', '-c', 'for p in /proc/[0-9]*/exe; do case "$(readlink "$p" 2>/dev/null)" in /usr/local/lsws/admin/fcgi-bin/admin_php*) pid=${p#/proc/}; pid=${pid%/exe}; kill -TERM "$pid" 2>/dev/null || true;; esac; done'])
    version = command(['docker', 'exec', container, target, '-v'])
    settings = command(['docker', 'exec', container, '/usr/local/lsws/lsphp82/bin/php', '-c', '/usr/local/lsws/admin/misc/php.ini', '-r', 'echo PHP_VERSION." ".ini_get("session.upload_progress.enabled");'])
    if not is_patched(version) or settings.strip().split()[-1] != '0':
        raise RuntimeError('webadmin_php_verification_failed')
    return {'runtime': settings.strip(), 'website_workers_restarted': False}
