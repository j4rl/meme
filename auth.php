<?php

declare(strict_types=1);

function meme_auth_config(): array
{
    static $config = null;

    if ($config !== null) {
        return $config;
    }

    $defaults = [
        'host' => 'localhost',
        'username' => 'root',
        'password' => '',
        'database' => 'meme',
        'table' => 'memeuser',
    ];

    $configFile = __DIR__ . DIRECTORY_SEPARATOR . 'auth_config.php';
    if (is_file($configFile)) {
        $loaded = require $configFile;
        if (is_array($loaded)) {
            $defaults = array_merge($defaults, $loaded);
        }
    }

    $config = $defaults;
    return $config;
}

function meme_auth_start_session(): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
}

function meme_auth_db(): mysqli
{
    $config = meme_auth_config();
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

    $mysqli = new mysqli(
        (string) $config['host'],
        (string) $config['username'],
        (string) $config['password'],
        (string) $config['database']
    );
    $mysqli->set_charset('utf8mb4');

    return $mysqli;
}

function meme_auth_column(array $columns, array $candidates): ?string
{
    foreach ($candidates as $candidate) {
        if (in_array($candidate, $columns, true)) {
            return $candidate;
        }
    }

    return null;
}

function meme_auth_load_user(mysqli $mysqli, string $login): ?array
{
    $config = meme_auth_config();
    $table = preg_replace('/[^A-Za-z0-9_]/', '', (string) $config['table']);
    if ($table === '') {
        throw new RuntimeException('Invalid user table name.');
    }

    $result = $mysqli->query('SHOW COLUMNS FROM `' . $table . '`');
    $columns = [];
    while ($row = $result->fetch_assoc()) {
        $columns[] = (string) $row['Field'];
    }

    $loginColumn = meme_auth_column($columns, ['username', 'email', 'user', 'name', 'namn', 'anvandarnamn']);
    $passwordColumn = meme_auth_column($columns, ['password_hash', 'password', 'losenord', 'pass']);

    if ($loginColumn === null || $passwordColumn === null) {
        throw new RuntimeException('Table memeuser needs a username/email column and a password column.');
    }

    $idColumn = meme_auth_column($columns, ['id', 'user_id', 'memeuser_id']) ?? $loginColumn;
    $sql = sprintf(
        'SELECT `%s` AS auth_id, `%s` AS auth_login, `%s` AS auth_password FROM `%s` WHERE `%s` = ? LIMIT 1',
        $idColumn,
        $loginColumn,
        $passwordColumn,
        $table,
        $loginColumn
    );

    $stmt = $mysqli->prepare($sql);
    $stmt->bind_param('s', $login);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();

    return is_array($user) ? $user : null;
}

function meme_auth_verify_password(string $password, string $storedPassword): bool
{
    return password_verify($password, $storedPassword);
}

function meme_auth_current_user(): ?array
{
    meme_auth_start_session();

    if (empty($_SESSION['meme_user'])) {
        return null;
    }

    return is_array($_SESSION['meme_user']) ? $_SESSION['meme_user'] : null;
}

function meme_auth_login_path(): string
{
    $requestUri = $_SERVER['REQUEST_URI'] ?? 'upload.php';
    $path = parse_url($requestUri, PHP_URL_PATH);
    $query = parse_url($requestUri, PHP_URL_QUERY);

    $target = basename(is_string($path) && $path !== '' ? $path : 'upload.php');
    if (is_string($query) && $query !== '') {
        $target .= '?' . $query;
    }

    return $target;
}

function meme_auth_handle_login(): array
{
    meme_auth_start_session();
    $errors = [];

    if (isset($_GET['logout'])) {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
        }
        session_destroy();
        header('Location: ' . strtok(meme_auth_login_path(), '?'));
        exit;
    }

    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST' || !isset($_POST['meme_login'])) {
        return $errors;
    }

    $login = trim((string) ($_POST['login'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');

    if ($login === '' || $password === '') {
        return ['Ange anvandarnamn och losenord.'];
    }

    try {
        $mysqli = meme_auth_db();
        $user = meme_auth_load_user($mysqli, $login);
    } catch (Throwable $exception) {
        return ['Kunde inte ansluta till anvandardatabasen: ' . $exception->getMessage()];
    }

    if ($user === null || !meme_auth_verify_password($password, (string) $user['auth_password'])) {
        return ['Fel anvandarnamn eller losenord.'];
    }

    session_regenerate_id(true);
    $_SESSION['meme_user'] = [
        'id' => (string) $user['auth_id'],
        'login' => (string) $user['auth_login'],
    ];

    header('Location: ' . meme_auth_login_path());
    exit;
}

function meme_auth_require_login(string $title = 'Logga in'): void
{
    $loginErrors = meme_auth_handle_login();

    if (meme_auth_current_user() !== null) {
        return;
    }

    $action = htmlspecialchars(meme_auth_login_path(), ENT_QUOTES);

    ?><!DOCTYPE html>
<html lang="sv">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($title, ENT_QUOTES); ?></title>
    <link rel="stylesheet" href="style.css">
</head>
<body class="upload-page login-page">
<div class="panel login-panel">
    <h1><?php echo htmlspecialchars($title, ENT_QUOTES); ?></h1>
    <p>Logga in for att administrera memes.</p>

    <?php if ($loginErrors): ?>
        <div class="messages">
            <?php foreach ($loginErrors as $error): ?>
                <div class="alert error"><?php echo htmlspecialchars($error, ENT_QUOTES); ?></div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <form method="post" action="<?php echo $action; ?>" class="upload-form">
        <input type="hidden" name="meme_login" value="1">
        <div class="input-field">
            <label class="field-label" for="login">Anvandarnamn eller e-post</label>
            <input type="text" id="login" name="login" autocomplete="username" required autofocus>
        </div>
        <div class="input-field">
            <label class="field-label" for="password">Losenord</label>
            <input type="password" id="password" name="password" autocomplete="current-password" required>
        </div>
        <button type="submit">Logga in</button>
    </form>

    <div class="links">
        <a href="index.php">Till visningslaget</a>
    </div>
</div>
</body>
</html>
<?php
    exit;
}

function meme_auth_user_link(): string
{
    $user = meme_auth_current_user();
    if ($user === null) {
        return '';
    }

    return sprintf(
        '<span class="auth-user">%s</span><a href="?logout=1">Logga ut</a>',
        htmlspecialchars((string) $user['login'], ENT_QUOTES)
    );
}
