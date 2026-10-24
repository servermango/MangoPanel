import subprocess
from pathlib import Path
from unittest.mock import patch
import pytest
from mangopanel.php_security import is_patched, update_account_php

@pytest.mark.parametrize('version,expected', [('8.3.35',False),('8.3.36',True),('8.2.35',True),('8.4.27',True),('8.5.12',True),('7.4.33',False),('invalid',False)])
def test_patch_baseline(version, expected):
    assert is_patched(version) is expected

def test_update_scopes_restart_and_preserves_branch(tmp_path):
    calls=[]
    def execute(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args,0,'ok','')
    with patch('mangopanel.php_security.subprocess.run',side_effect=execute), patch('mangopanel.php_security.update_legacy_php', return_value=[]):
        result=update_account_php({'id':1,'username':'u000001'},tmp_path)
    assert calls[0][:3]==['docker','exec','mp-u000001-web']
    assert 'cd / && tar -cf - usr/local/lsws/lsphp*' in calls[0][-1]
    assert calls[-1]==['docker','restart','-t','30','mp-u000001-web']
    script=next(c[-1] for c in calls if c[:4]==['docker','exec','mp-u000001-web','bash'])
    assert '--only-upgrade' in script
    assert 'session.upload_progress.enabled=0' in script
    assert 'rm -rf' not in script and 'compose' not in str(calls)
    assert result['php_branch_preserved']
    assert (Path(result['backup'])/'commands.log').stat().st_mode & 0o777 == 0o600

def test_failed_package_update_does_not_restart(tmp_path):
    def execute(args,**kwargs):
        return subprocess.CompletedProcess(args,1 if args[:4]==['docker','exec','mp-u000001-web','bash'] else 0,'','failure' if kwargs.get('text') else b'failure')
    with patch('mangopanel.php_security.subprocess.run',side_effect=execute) as run:
        with pytest.raises(RuntimeError):update_account_php({'id':1,'username':'u000001'},tmp_path)
    assert not any(c.args[0][1]=='restart' for c in run.call_args_list)

def test_invalid_account_never_executes(tmp_path):
    with patch('mangopanel.php_security.subprocess.run') as run:
        with pytest.raises(ValueError):update_account_php({'id':1,'username':'a;id'},tmp_path)
    run.assert_not_called()

def test_tool_compose_preserves_non_php_services_and_existing_mounts():
    from mangopanel.php_security import secure_tool_compose,TOOL_IMAGES
    original='''name: account
services:
  web:
    image: existing-web
  phpmyadmin:
    image: phpmyadmin:latest
    environment:
      PMA_PASSWORD: secret
    networks:
      - account
  mailproxy:
    image: old-mail
    volumes:
      - /mail:/var/lib/snappymail
    networks:
      - account
  db:
    image: mariadb:10.11
    volumes:
      - db-data:/var/lib/mysql
networks:
  account:
'''
    result=secure_tool_compose(original,'/account/php-security.ini')
    assert result.count('/zz-mangopanel-security.ini:ro')==2
    assert '      - /mail:/var/lib/snappymail' in result
    assert '    image: mariadb:10.11' in result
    assert '    image: existing-web' in result
    assert 'PMA_PASSWORD: secret' in result
    assert TOOL_IMAGES['mailproxy'] in result
    assert secure_tool_compose(result,'/account/php-security.ini')==result

def test_legacy_stages_use_official_pinned_sources():
    from mangopanel.php_legacy import legacy_security_stages,SOURCES
    text=legacy_security_stages()
    for branch,(_,commit) in SOURCES.items():
        assert f'https://codeload.github.com/php/php-src/tar.gz/{commit}' in text
        assert f'AS php{branch}_security\n' in text
        assert f'/usr/local/lsws/lsphp{branch}/PHP2SHELL-PATCHED' in text
    assert 'make -j2' in text

def test_panel_dispatch_rejects_inactive_account(tmp_path):
    import sqlite3
    from mangopanel.agent import Agent,AgentError
    c=sqlite3.connect(':memory:');c.row_factory=sqlite3.Row
    c.execute('create table hosting_accounts (id integer, username text, status text)')
    c.execute("insert into hosting_accounts values (1,'u000001','suspended')")
    with patch('mangopanel.php_security.update_account_php') as update:
        with pytest.raises(AgentError,match='active_hosting_account_required'):
            Agent().dispatch(c,{'type':'update_account_php_security','target_id':1})
    update.assert_not_called()

@pytest.mark.parametrize('preserve',[True,False])
def test_legacy_extensions_validated_before_activation(tmp_path,preserve):
    import json
    from mangopanel.php_security import update_legacy_php
    from mangopanel.php_legacy import SOURCES
    calls=[]
    def command(args,timeout=None):
        calls.append(args)
        joined=' '.join(args)
        if args[1:3]==['images','-q']:return 'image-id'
        if 'PHP2SHELL-PATCHED' in joined and args[1]=='run':return SOURCES['74'][1]
        if 'PHP2SHELL-COMPATIBILITY' in joined and args[1]=='run':return 'sysvmsg'
        if args[1]=='create':return 'scratch-id'
        if '-r' in args:
            return json.dumps(['json','mysqli','sysvmsg'] if preserve or '/bin/php.security-new' not in joined else ['json','mysqli'])
        if 'for v in 74 80 81' in joined:return '74\n80\n'
        return ''
    if preserve:
        assert update_legacy_php('mp-u000001-web',tmp_path,command,versions={'74'})==['74']
        assert any(a[1:4]==['exec','mp-u000001-web','mv'] for a in calls)
    else:
        with pytest.raises(RuntimeError,match='legacy_extensions_would_be_lost: sysvmsg'):
            update_legacy_php('mp-u000001-web',tmp_path,command,versions={'74'})
        assert not any(a[1:4]==['exec','mp-u000001-web','mv'] for a in calls)

def test_modern_accounts_build_legacy_only_when_selected(tmp_path):
    from mangopanel.config import Config
    from mangopanel.db import connect,seed_dev_data,create_job
    from mangopanel.agent import Agent
    config=Config();config.db_path=tmp_path/'panel.db';config.data_dir=tmp_path;config.account_root=tmp_path/'accounts';config.agent_mode='simulate'
    seed_dev_data(config.db_path,config.account_root);Agent(config).run_all()
    p=config.account_root/'u000001/.runtime/stack/web/Dockerfile'
    initial=p.read_text()
    assert 'COPY --from=php74_security /usr/local/lsws/lsphp74' not in initial
    assert 'PHP2Shell-20261025' in initial
    with connect(config.db_path) as c:
        website=c.execute('select id from websites order by id limit 1').fetchone()
        c.execute("update websites set php_version='7.4' where id=?",(website['id'],))
        job=create_job(c,'update_website_php','website',website['id'],{})
    result=Agent(config).run_job_by_id(job)
    assert result['status']=='succeeded'
    changed=p.read_text()
    assert 'COPY --from=php74_security /usr/local/lsws/lsphp74' in changed
    assert 'COPY --from=php80_security /usr/local/lsws/lsphp80' not in changed
