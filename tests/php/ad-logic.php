<?php
session_start();

if (!isset($_SESSION['user'])) {
    // ruleid: php-redirect-without-exit
    header("Location: login.php");
}

if (!isset($_SESSION['admin'])) {
    // ok: php-redirect-without-exit
    header("Location: login.php");
    exit;
}

// ruleid: php-cookie-based-authorization
if ($_COOKIE['is_admin'] == "1") {
    echo file_get_contents('/flag');
}

function reset_token() {
    // ruleid: php-weak-random-token
    return md5(uniqid());
}

function good_token() {
    // ok: php-weak-random-token
    return bin2hex(random_bytes(16));
}

function issue($user) {
    // ruleid: php-hardcoded-jwt-key
    return JWT::encode(['sub' => $user], "secret123", 'HS256');
}

function check_sig($data, $signature, $key) {
    // ruleid: php-timing-unsafe-secret-compare
    if ($signature == hash_hmac('sha256', $data, $key)) {
        return true;
    }
    // ok: php-timing-unsafe-secret-compare
    return hash_equals(hash_hmac('sha256', $data, $key), (string) $signature);
}

function allowed($role) {
    // ruleid: php-in-array-loose
    $a = in_array($role, ['user', 'guest']);
    // ok: php-in-array-loose
    $b = in_array($role, ['user', 'guest'], true);
    return $a && $b;
}

function validate_host($h) {
    // ruleid: php-preg-match-dollar-allows-newline
    if (!preg_match('/^[a-z0-9.]+$/', $h)) {
        die("bad");
    }
    // ok: php-preg-match-dollar-allows-newline
    if (!preg_match('/^[a-z0-9.]+$/D', $h)) {
        die("bad");
    }
    // ruleid: php-preg-match-unanchored-validation
    if (!preg_match('/[a-z0-9.]+/', $h)) {
        die("bad");
    }
    return $h;
}

function store($request) {
    // ruleid: php-laravel-mass-assignment
    return User::create($request->all());
}

// ruleid: php-laravel-mass-assignment
class Note extends Model {
    protected $guarded = [];
}

function debug() {
    // ruleid: php-phpinfo-or-debug-exposed
    phpinfo();
}

function login_as() {
    // ruleid: php-session-fixation-user-id
    $_SESSION['user_id'] = $_GET['uid'];
}

function parse_xml($xml) {
    // ruleid: php-xxe-noent
    return simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);
}
