<?php

function get_user($conn) {
    $id = $_GET['id'];
    $sql = "SELECT * FROM users WHERE id = '" . $id . "'";
    // ruleid: php-taint-sqli
    $res = mysqli_query($conn, $sql);
    $n = intval($_GET['n']);
    // ok: php-taint-sqli
    $res2 = mysqli_query($conn, "SELECT * FROM users LIMIT " . $n);
    return [$res, $res2];
}

function search($pdo) {
    $q = $_POST['q'];
    // ruleid: php-taint-sqli
    $stmt = $pdo->query("SELECT * FROM notes WHERE title LIKE '%$q%'");
    // ok: php-taint-sqli
    $stmt2 = $pdo->prepare("SELECT * FROM notes WHERE title LIKE ?");
    $stmt2->execute(["%$q%"]);
    return $stmt;
}

function ping() {
    $host = $_GET['host'];
    // ruleid: php-taint-command-injection
    system("ping -c 1 " . $host);
    // ok: php-taint-command-injection
    system("ping -c 1 " . escapeshellarg($host));
}

function calc() {
    $f = $_GET['f'];
    // ruleid: php-taint-code-injection
    $f($_GET['a']);
    // ruleid: php-taint-code-injection
    eval('return ' . $_POST['expr'] . ';');
}

function page() {
    $p = $_GET['page'];
    // ruleid: php-taint-file-inclusion
    include "pages/" . $p . ".php";
    // ok: php-taint-file-inclusion
    include "pages/" . basename($p) . ".php";
}

function download() {
    $name = $_GET['file'];
    // ruleid: php-taint-path-traversal
    readfile("/var/www/uploads/" . $name);
    // ok: php-taint-path-traversal
    readfile("/var/www/uploads/" . basename($name));
}

function fetch_url() {
    $url = $_POST['url'];
    $ch = curl_init();
    // ruleid: php-taint-ssrf
    curl_setopt($ch, CURLOPT_URL, $url);
    return curl_exec($ch);
}

function restore() {
    $data = base64_decode($_COOKIE['prefs']);
    // ruleid: php-taint-deserialization
    $prefs = unserialize($data);
    // ok: php-taint-deserialization
    $safe = unserialize($data, ['allowed_classes' => false]);
    return [$prefs, $safe];
}

function hello() {
    $name = $_GET['name'];
    // ruleid: php-taint-xss
    echo "<h1>Hello " . $name . "</h1>";
    // ok: php-taint-xss
    echo "<h1>Hello " . htmlspecialchars($name) . "</h1>";
}

function preview($twig) {
    $tpl = "Dear " . $_POST['name'];
    // ruleid: php-taint-ssti
    return $twig->createTemplate($tpl)->render([]);
}

function go() {
    // ruleid: php-taint-open-redirect-header-injection
    header("Location: " . $_GET['next']);
}

function settings() {
    $is_admin = false;
    // ruleid: php-taint-variable-overwrite
    extract($_POST);
    // ruleid: php-taint-variable-overwrite
    parse_str($_SERVER['QUERY_STRING']);
    // ok: php-taint-variable-overwrite
    parse_str($_SERVER['QUERY_STRING'], $out);
    return $is_admin;
}

function filter_notes($notes) {
    $re = $_GET['re'];
    // ruleid: php-taint-regex-injection
    return preg_grep_wrapper(preg_match("/" . $re . "/", $notes));
}

function upload() {
    $name = $_FILES['avatar']['name'];
    $dest = "/var/www/html/uploads/" . $name;
    // ruleid: php-taint-upload-filename, php-taint-path-traversal
    move_uploaded_file($_FILES['avatar']['tmp_name'], $dest);
    // ok: php-taint-upload-filename
    move_uploaded_file($_FILES['avatar']['tmp_name'], "/var/www/html/uploads/" . bin2hex(random_bytes(16)) . ".png");
}
