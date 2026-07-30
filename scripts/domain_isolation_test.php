<?php
/**
 * Domain isolation test for MangoPanel per-account / per-domain separation.
 *
 * Place this file in one site's public_html and run it from that site.
 * It will attempt to access sibling domains under the same account.
 *
 * Usage:
 *  - web: visit http://your-domain/path/to/domain_isolation_test.php
 *  - cli: php scripts/domain_isolation_test.php
 */

error_reporting(E_ALL);
ini_set('display_errors', '1');
set_time_limit(0);

function heading($title)
{
    echo "\n## {$title}\n\n";
}

function resultLine($name, $ok, $message = null)
{
    $checkbox = $ok ? '[x]' : '[ ]';
    echo "- {$checkbox} {$name}";
    if ($message !== null) {
        echo " - " . trim($message);
    }
    echo "\n";
}

function isFunctionEnabled($name)
{
    if (!function_exists($name)) {
        return false;
    }
    $disabled = explode(',', ini_get('disable_functions'));
    $disabled = array_map('trim', $disabled);
    return $disabled === [''] ? true : !in_array($name, $disabled, true);
}

function dangerousFunctions()
{
    return [
        'exec', 'passthru', 'shell_exec', 'system', 'proc_open', 'popen',
        'pcntl_exec', 'pcntl_fork', 'pcntl_waitpid', 'pcntl_wait',
        'pcntl_signal', 'pcntl_signal_dispatch', 'pcntl_alarm',
        'pcntl_getpriority', 'pcntl_setpriority', 'pcntl_wifexited',
        'pcntl_wexitstatus', 'pcntl_wifsignaled', 'pcntl_wtermsig',
        'pcntl_wifstopped', 'pcntl_wstopsig', 'pcntl_sigprocmask',
        'pcntl_sigwaitinfo', 'pcntl_async_signals', 'curl_exec',
        'curl_multi_exec', 'parse_ini_file', 'show_source', 'symlink',
        'link', 'rename', 'copy', 'file_put_contents', 'chmod', 'chown',
        'chgrp', 'unlink', 'rmdir', 'mkdir', 'fopen', 'fwrite', 'readfile',
        'opendir', 'scandir', 'glob', 'php_uname', 'passthru', 'proc_get_status',
        'posix_kill', 'posix_mkfifo', 'posix_getpwuid', 'posix_getgrgid',
        'mail', 'fsockopen', 'pfsockopen', 'socket_create', 'socket_connect',
        'stream_socket_client'
    ];
}

function reportDangerousFunctions()
{
    heading('Dangerous PHP function availability');
    $disabled = array_map('trim', explode(',', ini_get('disable_functions')));
    if ($disabled === ['']) {
        $disabled = [];
    }
    foreach (dangerousFunctions() as $fn) {
        $available = function_exists($fn) ? 'available' : 'missing';
        $disabledState = in_array($fn, $disabled, true) ? 'disabled' : 'enabled';
        resultLine($fn, $available === 'available' && $disabledState === 'enabled', "$available, $disabledState");
    }
}

function safeCall($name, callable $fn)
{
    try {
        return $fn();
    } catch (Throwable $e) {
        return 'EXCEPTION: ' . $e->getMessage();
    }
}

function safeShell($command)
{
    $command = str_replace("\n", ' ', $command);
    if (isFunctionEnabled('shell_exec')) {
        return @shell_exec($command);
    }
    if (isFunctionEnabled('exec')) {
        $output = [];
        @exec($command, $output, $rc);
        return implode("\n", $output);
    }
    if (isFunctionEnabled('system')) {
        ob_start();
        @system($command, $rc);
        return ob_get_clean();
    }
    if (isFunctionEnabled('passthru')) {
        ob_start();
        @passthru($command, $rc);
        return ob_get_clean();
    }
    if (isFunctionEnabled('popen')) {
        $handle = @popen($command, 'r');
        if ($handle) {
            $data = @stream_get_contents($handle);
            @pclose($handle);
            return $data;
        }
    }
    if (isFunctionEnabled('proc_open')) {
        $descriptors = [
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $process = @proc_open($command, $descriptors, $pipes);
        if (is_resource($process)) {
            $data = '';
            $data .= @stream_get_contents($pipes[1]);
            $data .= @stream_get_contents($pipes[2]);
            @fclose($pipes[1]);
            @fclose($pipes[2]);
            @proc_close($process);
            return $data;
        }
    }

    return 'disabled or unavailable';
}

function checkFileAccess($path)
{
    $tests = [];
    $tests['file_exists'] = @file_exists($path);
    $tests['is_readable'] = @is_readable($path);
    $tests['is_file'] = @is_file($path);
    $tests['is_dir'] = @is_dir($path);
    $tests['realpath'] = @realpath($path);
    $tests['fopen'] = false;
    $handle = @fopen($path, 'rb');
    if ($handle) {
        $tests['fopen'] = true;
        @fclose($handle);
    }
    $tests['file_get_contents'] = false;
    $content = @file_get_contents($path);
    if ($content !== false) {
        $tests['file_get_contents'] = true;
        $tests['file_get_contents_length'] = strlen($content);
    }
    $tests['readfile'] = false;
    ob_start();
    $bytes = @readfile($path);
    $dump = ob_get_clean();
    if ($bytes !== false && $bytes !== 0) {
        $tests['readfile'] = true;
        $tests['readfile_bytes'] = $bytes;
    }
    $tests['php_strip_whitespace'] = false;
    if (function_exists('php_strip_whitespace')) {
        $stripped = @php_strip_whitespace($path);
        if ($stripped !== false) {
            $tests['php_strip_whitespace'] = true;
            $tests['php_strip_whitespace_length'] = strlen($stripped);
        }
    }
    $tests['copy_to_tmp'] = false;
    $tmp = sys_get_temp_dir() . '/isolation_test_copy_' . uniqid();
    if (@copy($path, $tmp)) {
        $tests['copy_to_tmp'] = true;
        @unlink($tmp);
    }
    $tests['stream_wrapper_file'] = false;
    $fileUri = 'file://' . $path;
    $data = @file_get_contents($fileUri);
    if ($data !== false) {
        $tests['stream_wrapper_file'] = true;
        $tests['stream_wrapper_length'] = strlen($data);
    }
    $tests['glob'] = false;
    $globResult = @glob($path);
    if ($globResult !== false && count($globResult) > 0) {
        $tests['glob'] = true;
        $tests['glob_count'] = count($globResult);
    }
    $tests['scandir'] = false;
    $scan = @scandir(dirname($path));
    if ($scan !== false) {
        $tests['scandir'] = true;
        $tests['scandir_count'] = count($scan);
    }
    return $tests;
}

function trySymlink($target)
{
    $tmp = sys_get_temp_dir() . '/isolation_test_link_' . uniqid();
    if (!function_exists('symlink')) {
        return ['created' => false, 'read' => 'symlink unavailable'];
    }
    $created = @symlink($target, $tmp);
    $result = ['created' => (bool) $created, 'read' => false, 'read_error' => null];
    if ($created) {
        $content = @file_get_contents($tmp);
        if ($content !== false) {
            $result['read'] = true;
            $result['content_length'] = strlen($content);
        } else {
            $result['read'] = false;
            $result['read_error'] = error_get_last()['message'] ?? 'unknown';
        }
        @unlink($tmp);
    }
    return $result;
}

function testShellPath($path)
{
    $command = 'printf "PATH_OK\n" && cat ' . escapeshellarg($path) . ' 2>&1';
    $output = safeShell($command);
    return trim((string)$output);
}

function testCurlPath($path)
{
    if (!function_exists('curl_init')) {
        return 'curl unavailable';
    }
    $uri = 'file://' . $path;
    $ch = curl_init($uri);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_VERBOSE, false);
    $result = @curl_exec($ch);
    $err = curl_error($ch);
    curl_close($ch);
    if ($result === false) {
        return 'curl failed: ' . $err;
    }
    return 'curl success length=' . strlen($result);
}

function tryDisableOpenBasedir($path)
{
    $results = [];
    $original = ini_get('open_basedir');
    $results['current'] = $original;

    $results['read_before'] = @file_get_contents($path) !== false;
    $results['ini_set_empty'] = false;
    $results['ini_set_empty_read'] = false;
    $results['ini_set_none'] = false;
    $results['ini_set_none_read'] = false;
    $results['ini_restore'] = false;
    $results['ini_restore_read'] = false;
    $results['ini_set_temp'] = false;
    $results['ini_set_temp_read'] = false;

    if (function_exists('ini_set')) {
        $set = @ini_set('open_basedir', '');
        $results['ini_set_empty'] = $set !== false;
        $results['ini_set_empty_read'] = @file_get_contents($path) !== false;
        @ini_set('open_basedir', $original);

        $set = @ini_set('open_basedir', 'none');
        $results['ini_set_none'] = $set !== false;
        $results['ini_set_none_read'] = @file_get_contents($path) !== false;
        @ini_set('open_basedir', $original);

        $set = @ini_set('open_basedir', sys_get_temp_dir());
        $results['ini_set_temp'] = $set !== false;
        $results['ini_set_temp_read'] = @file_get_contents($path) !== false;
        @ini_set('open_basedir', $original);
    }

    if (function_exists('ini_restore')) {
        @ini_restore('open_basedir');
        $results['ini_restore'] = true;
        $results['ini_restore_read'] = @file_get_contents($path) !== false;
        @ini_set('open_basedir', $original);
    }

    return $results;
}

function attemptWrapperAccess($path)
{
    $wrappers = [
        'file://' . $path,
        'php://filter/convert.base64-encode/resource=' . $path,
        'phar://' . $path,
        'zip://' . $path . '#index.php',
        'expect://cat ' . escapeshellarg($path),
    ];
    $results = [];
    foreach ($wrappers as $wrapper) {
        $contents = @file_get_contents($wrapper);
        $results[$wrapper] = $contents === false ? 'failed' : 'success len=' . strlen($contents);
    }
    return $results;
}

function attemptShowSource($path)
{
    if (!function_exists('show_source')) {
        return 'unavailable';
    }
    $source = @show_source($path, true);
    return $source === false ? 'failed' : 'success len=' . strlen($source);
}

function attemptMkdirRmdir($path)
{
    $results = [];
    $dir = rtrim($path, '/') . '/isolation_test_dir_' . uniqid();
    $results['mkdir'] = @mkdir($dir, 0700);
    if ($results['mkdir']) {
        $results['exists'] = is_dir($dir);
        $results['rmdir'] = @rmdir($dir);
    } else {
        $results['exists'] = false;
        $results['rmdir'] = false;
    }
    return $results;
}

function tryBacktickExecution($command)
{
    if (!isFunctionEnabled('shell_exec')) {
        return 'not available';
    }
    $output = null;
    try {
        $output = `{$command}`;
    } catch (Throwable $e) {
        return 'exception';
    }
    return $output === null ? 'failed' : 'success len=' . strlen($output);
}

function resolveDocumentRoot()
{
    if (!empty($_SERVER['DOCUMENT_ROOT'])) {
        return realpath($_SERVER['DOCUMENT_ROOT']);
    }
    if (count($GLOBALS['argv']) > 1) {
        return realpath($GLOBALS['argv'][1]);
    }
    return realpath(getcwd());
}

function tryWrite($path)
{
    $results = [];
    $testFile = rtrim($path, '/') . '/isolation_write_test_' . uniqid() . '.txt';
    $contents = "isolation-test-" . time() . "\n";

    $results['touch'] = @touch($testFile);
    if ($results['touch']) {
        $results['touch_size'] = filesize($testFile);
    }

    $results['file_put_contents'] = false;
    if (@file_put_contents($testFile, $contents) !== false) {
        $results['file_put_contents'] = true;
    }

    $results['fopen_fwrite'] = false;
    $handle = @fopen($testFile, 'ab');
    if ($handle) {
        if (@fwrite($handle, $contents) !== false) {
            $results['fopen_fwrite'] = true;
        }
        @fclose($handle);
    }

    $tmp = sys_get_temp_dir() . '/isolation_write_tmp_' . uniqid() . '.txt';
    @file_put_contents($tmp, $contents);
    $results['rename_into'] = false;
    if (file_exists($tmp) && @rename($tmp, $testFile)) {
        $results['rename_into'] = true;
    }
    @unlink($tmp);

    $results['copy_into'] = false;
    $tmp = sys_get_temp_dir() . '/isolation_write_copy_' . uniqid() . '.txt';
    @file_put_contents($tmp, $contents);
    if (file_exists($tmp) && @copy($tmp, $testFile)) {
        $results['copy_into'] = true;
    }
    @unlink($tmp);

    $results['final_exists'] = file_exists($testFile);
    $results['final_read'] = false;
    if ($results['final_exists']) {
        $results['final_read'] = @file_get_contents($testFile) !== false;
    }
    @unlink($testFile);
    return $results;
}

function locateDomainsRoot($documentRoot)
{
    $candidates = [
        dirname(dirname($documentRoot)),
        realpath($documentRoot . '/../../domains'),
        realpath(dirname($documentRoot, 2) . '/domains'),
        realpath(__DIR__ . '/../../domains'),
        realpath(__DIR__ . '/../../../domains'),
    ];
    foreach ($candidates as $candidate) {
        if ($candidate && is_dir($candidate)) {
            return $candidate;
        }
    }
    return false;
}

function traverseDiscovery($path, $maxDepth = 3, $maxEntries = 200)
{
    $result = [
        'root' => $path,
        'files' => [],
        'dirs' => [],
        'count' => 0,
        'errors' => [],
    ];

    if (!is_dir($path)) {
        $result['errors'][] = 'not a directory';
        return $result;
    }

    $scan = function ($dir, $depth) use (&$scan, &$result, $maxDepth, $maxEntries) {
        if ($depth < 0 || $result['count'] >= $maxEntries) {
            return;
        }
        $items = @scandir($dir);
        if ($items === false) {
            $result['errors'][] = 'scandir failed: ' . $dir;
            return;
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $full = $dir . '/' . $item;
            $result['count']++;
            if (is_dir($full)) {
                $result['dirs'][] = $full;
                $scan($full, $depth - 1);
            } else {
                $result['files'][] = $full;
            }
            if ($result['count'] >= $maxEntries) {
                return;
            }
        }
    };

    $scan($path, $maxDepth);
    return $result;
}

function tryTraversalCandidates($documentRoot)
{
    $candidates = [
        $documentRoot . '/../../domains',
        $documentRoot . '/../../../domains',
        dirname($documentRoot, 2) . '/domains',
        __DIR__ . '/../../domains',
        __DIR__ . '/../../../domains',
    ];
    $results = [];
    foreach ($candidates as $candidate) {
        $real = realpath($candidate);
        if ($real && is_dir($real)) {
            $results[$candidate] = $real;
        } else {
            $results[$candidate] = false;
        }
    }
    return $results;
}

function tryChangePermissions($path)
{
    $result = [
        'path' => $path,
        'exists' => file_exists($path),
        'is_file' => is_file($path),
        'orig_perms' => null,
        'chmod_0600' => false,
        'chmod_restore' => false,
        'chown' => null,
        'chgrp' => null,
    ];

    if (!$result['exists']) {
        return $result;
    }

    $origPerms = @fileperms($path);
    if ($origPerms !== false) {
        $result['orig_perms'] = sprintf('%04o', $origPerms & 0777);
    }

    if (function_exists('chmod')) {
        $result['chmod_0600'] = @chmod($path, 0600);
        if ($result['chmod_0600'] && $origPerms !== false) {
            $result['chmod_restore'] = @chmod($path, $origPerms & 0777);
        }
    }
    if (function_exists('chown') && function_exists('getmyuid')) {
        $result['chown'] = @chown($path, getmyuid());
    }
    if (function_exists('chgrp') && function_exists('getmygid')) {
        $result['chgrp'] = @chgrp($path, getmygid());
    }

    return $result;
}

$documentRoot = resolveDocumentRoot();
if ($documentRoot === false) {
    echo "Unable to resolve current document root.\n";
    exit(1);
}

$currentDomainRoot = dirname($documentRoot);
$domainsRoot = locateDomainsRoot($documentRoot);
$accountRoot = $domainsRoot ? dirname($domainsRoot) : dirname(dirname($currentDomainRoot));
$currentDomain = basename($currentDomainRoot);

heading('Domain Isolation Test');
resultLine('Current document root', true, $documentRoot);
resultLine('Current domain', true, $currentDomain);
resultLine('Domains root', $domainsRoot !== false, $domainsRoot ?: 'not found');
resultLine('Account root', true, $accountRoot);
resultLine('Open_basedir', ini_get('open_basedir') !== false, ini_get('open_basedir'));
resultLine('Disable functions', true, ini_get('disable_functions'));

echo "\n";
reportDangerousFunctions();

if (!$domainsRoot) {
    heading('Traversal candidate discovery');
    $traversalCandidates = tryTraversalCandidates($documentRoot);
    foreach ($traversalCandidates as $candidate => $real) {
        resultLine('candidate', $real !== false, "$candidate -> " . ($real ?: 'none'));
    }
}

$otherDomains = [];
foreach ((array) glob($domainsRoot . '/*', GLOB_ONLYDIR) as $candidate) {
    if ($candidate === $currentDomainRoot) {
        continue;
    }
    $publicHtml = $candidate . '/public_html';
    if (is_dir($publicHtml)) {
        $otherDomains[$candidate] = $publicHtml;
    }
}

if (empty($otherDomains)) {
    echo "No sibling domains found under same account. Please place this script inside a public_html and ensure sibling domains exist.\n";
    exit(1);
}

foreach ($otherDomains as $domainRoot => $publicHtml) {
    heading('Testing sibling domain: ' . basename($domainRoot));
    resultLine('Target sibling document root', true, $publicHtml);
    $probeFiles = [
        $publicHtml . '/index.php',
        $publicHtml . '/wp-config.php',
        $publicHtml . '/wp-config-sample.php',
        $publicHtml . '/.htaccess',
    ];
    foreach ($probeFiles as $probe) {
        $exists = file_exists($probe);
        resultLine('probe:' . basename($probe), $exists, $probe);
    }

    heading('Traversal and discovery');
    $candidatePaths = tryTraversalCandidates($publicHtml);
    foreach ($candidatePaths as $candidate => $real) {
        resultLine('traverse:' . basename($candidate), $real !== false, ($real ?: 'no path'));
    }
    $discovery = traverseDiscovery($publicHtml, 3, 120);
    resultLine('discovery_count', $discovery['count'] > 0, 'files=' . count($discovery['files']) . ' dirs=' . count($discovery['dirs']) . ' errors=' . count($discovery['errors']));
    if (!empty($discovery['errors'])) {
        foreach ($discovery['errors'] as $error) {
            echo "  error: {$error}\n";
        }
    }
    foreach (array_slice($discovery['dirs'], 0, 10) as $dir) {
        echo "  dir: {$dir}\n";
    }
    foreach (array_slice($discovery['files'], 0, 10) as $file) {
        echo "  file: {$file}\n";
    }

    heading('Permission change tests');
    $permissionResult = tryChangePermissions($publicHtml . '/index.php');
    foreach ($permissionResult as $name => $value) {
        if ($name === 'path') {
            continue;
        }
        resultLine('perm_' . $name, (bool) $value, json_encode($value));
    }

    heading('open_basedir bypass attempts');
    $openBasedirResults = tryDisableOpenBasedir($publicHtml . '/index.php');
    foreach ($openBasedirResults as $name => $value) {
        if ($name === 'current') {
            resultLine('open_basedir current', true, $value);
            continue;
        }
        $ok = is_bool($value) ? $value : ($value !== false);
        resultLine('open_basedir_' . $name, $ok, json_encode($value));
    }

    heading('Wrapper/file source tests');
    $wrapperResults = attemptWrapperAccess($publicHtml . '/index.php');
    foreach ($wrapperResults as $wrapper => $result) {
        resultLine('wrapper', strpos($result, 'success') !== false, "$wrapper -> $result");
    }
    $showSource = attemptShowSource($publicHtml . '/index.php');
    resultLine('show_source', strpos($showSource, 'success') !== false, $showSource);

    heading('mkdir/rmdir tests');
    $mkdirResults = attemptMkdirRmdir($publicHtml);
    foreach ($mkdirResults as $name => $value) {
        resultLine('mkdir_' . $name, (bool) $value, json_encode($value));
    }

    heading('backtick execution test');
    $backtick = tryBacktickExecution('echo BACKTICK_OK');
    resultLine('backtick', strpos($backtick, 'success') !== false, $backtick);

    $fileTests = checkFileAccess($publicHtml . '/index.php');

    foreach ($fileTests as $name => $value) {
        if (is_bool($value)) {
            resultLine($name, $value, '' );
        } else {
            resultLine($name, (bool)$value, json_encode($value));
        }
    }

    heading('Stream and wrapper tests');
    $streamResults = [];
    $streamResults['file_uri'] = testCurlPath($publicHtml . '/index.php');
    $streamResults['php_filter'] = safeCall('php_filter', function () use ($publicHtml) {
        $uri = 'php://filter/convert.base64-encode/resource=' . $publicHtml . '/index.php';
        $data = @file_get_contents($uri);
        return $data === false ? 'failed' : 'success len=' . strlen($data);
    });
    foreach ($streamResults as $name => $value) {
        resultLine($name, strpos((string)$value, 'success') !== false, (string)$value);
    }

    heading('Write and create tests');
    $writeResults = tryWrite($publicHtml);
    foreach ($writeResults as $name => $value) {
        resultLine($name, (bool)$value, json_encode($value));
    }

    heading('Shell execution tests');
    $shellTests = [];
    $shellTests['cat'] = testShellPath($publicHtml . '/index.php');
    $shellTests['ls'] = testShellPath(dirname($publicHtml));
    foreach ($shellTests as $name => $output) {
        $ok = strpos($output, 'PATH_OK') !== false && strpos($output, 'No such file or directory') === false;
        resultLine($name, $ok, substr($output, 0, 200));
    }

    heading('Process/stream based shell tests');
    $procTests = [];
    if (isFunctionEnabled('popen')) {
        $handle = @popen('cat ' . escapeshellarg($publicHtml . '/index.php') . ' 2>&1', 'r');
        $procTests['popen'] = $handle ? trim(stream_get_contents($handle)) : 'failed';
        if ($handle) {@pclose($handle);}    
    } else {
        $procTests['popen'] = 'disabled';
    }
    if (isFunctionEnabled('proc_open')) {
        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = @proc_open('cat ' . escapeshellarg($publicHtml . '/index.php') . ' 2>&1', $descriptors, $pipes);
        if (is_resource($process)) {
            $output = stream_get_contents($pipes[1]);
            $output .= stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            @proc_close($process);
            $procTests['proc_open'] = trim($output);
        } else {
            $procTests['proc_open'] = 'failed';
        }
    } else {
        $procTests['proc_open'] = 'disabled';
    }
    foreach ($procTests as $name => $output) {
        $ok = is_string($output) && strlen($output) > 0 && strpos($output, 'No such file or directory') === false && $output !== 'disabled';
        resultLine($name, $ok, substr((string)$output, 0, 200));
    }

    heading('Symlink test');
    $symlinkResult = trySymlink($publicHtml . '/index.php');
    if ($symlinkResult['created']) {
        resultLine('symlink_created', true, 'created');
        resultLine('symlink_read', (bool)$symlinkResult['read'], json_encode($symlinkResult));
    } else {
        resultLine('symlink_created', false, $symlinkResult['read']);
    }

    heading('Access control summary');
    $successes = [];
    foreach ($fileTests as $key => $value) {
        if ($value) {
            $successes[] = "file_test:$key";
        }
    }
    if (strpos((string)$streamResults['file_uri'], 'success') !== false) {
        $successes[] = 'stream_file';
    }
    if (strpos((string)$streamResults['php_filter'], 'success') !== false) {
        $successes[] = 'php_filter';
    }
    if ($shellTests['cat'] && strpos($shellTests['cat'], 'PATH_OK') !== false) {
        $successes[] = 'shell_cat';
    }
    if ($procTests['popen'] && $procTests['popen'] !== 'disabled' && $procTests['popen'] !== 'failed') {
        $successes[] = 'popen';
    }
    if ($procTests['proc_open'] && $procTests['proc_open'] !== 'disabled' && $procTests['proc_open'] !== 'failed') {
        $successes[] = 'proc_open';
    }
    if ($symlinkResult['created'] && $symlinkResult['read']) {
        $successes[] = 'symlink';
    }
    if (empty($successes)) {
        resultLine('isolation', true, 'No sibling-domain access methods succeeded.');
    } else {
        resultLine('isolation', false, 'These methods succeeded: ' . implode(', ', $successes));
    }
}

heading('Test complete');
