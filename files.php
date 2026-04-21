<?php
require_once __DIR__ . DIRECTORY_SEPARATOR . 'auth.php';
meme_auth_require_login('Logga in till filhantering');

$uploadsDir = __DIR__ . DIRECTORY_SEPARATOR . 'uploads';
$settingsFile = __DIR__ . DIRECTORY_SEPARATOR . 'settings.json';
$logFile = __DIR__ . DIRECTORY_SEPARATOR . 'image_log.json';
$allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
$expireDays = 300;
$errors = [];
$messages = [];

if (!is_dir($uploadsDir)) {
    $errors[] = 'The uploads directory is missing.';
}

if (is_file($settingsFile)) {
    $settings = json_decode((string) file_get_contents($settingsFile), true);
    if (is_array($settings) && isset($settings['expire_days']) && is_numeric($settings['expire_days'])) {
        $expireDays = max(1, (int) $settings['expire_days']);
    }
}

$expireSeconds = $expireDays * 86400;

$imageLog = [];
if (is_file($logFile)) {
    $decodedLog = json_decode((string) file_get_contents($logFile), true);
    if (is_array($decodedLog)) {
        $imageLog = $decodedLog;
    }
}

$now = time();
$logChanged = false;

$normalizeFileName = static function (string $input) use ($allowedExtensions): ?string {
    $basename = basename($input);
    $extension = strtolower(pathinfo($basename, PATHINFO_EXTENSION));

    if ($basename !== $input || !in_array($extension, $allowedExtensions, true)) {
        return null;
    }

    return $basename;
};

$deleteFileFromDisk = static function (string $file) use (&$imageLog, &$logChanged, $uploadsDir, &$errors): bool {
    $targetPath = $uploadsDir . DIRECTORY_SEPARATOR . $file;

    if (!is_file($targetPath)) {
        $errors[] = sprintf('File "%s" could not be found on disk.', $file);
        unset($imageLog[$file]);
        $logChanged = true;
        return false;
    }

    if (!@unlink($targetPath)) {
        $errors[] = sprintf('Unable to delete "%s".', $file);
        return false;
    }

    unset($imageLog[$file]);
    $logChanged = true;

    return true;
};

$formatBytes = static function (int $bytes): string {
    if ($bytes < 1024) {
        return $bytes . ' B';
    }

    $units = ['KB', 'MB', 'GB', 'TB'];
    $value = $bytes / 1024;
    foreach ($units as $unit) {
        if ($value < 1024) {
            return number_format($value, 1) . ' ' . $unit;
        }

        $value /= 1024;
    }

    return number_format($value, 1) . ' PB';
};

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['delete_file'])) {
        $fileToDelete = $normalizeFileName((string) $_POST['delete_file']);

        if ($fileToDelete === null) {
            $errors[] = 'Invalid file selected for deletion.';
        } elseif ($deleteFileFromDisk($fileToDelete)) {
            $messages[] = sprintf('Deleted %s.', $fileToDelete);
        }
    } elseif (isset($_POST['delete_selected'])) {
        $selectedFiles = $_POST['selected_files'] ?? [];
        if (!is_array($selectedFiles) || !$selectedFiles) {
            $errors[] = 'Select at least one file before deleting.';
        } else {
            $normalized = [];
            foreach ($selectedFiles as $name) {
                $normalizedName = $normalizeFileName((string) $name);
                if ($normalizedName !== null) {
                    $normalized[$normalizedName] = true;
                }
            }

            if (!$normalized) {
                $errors[] = 'No valid files were selected.';
            } else {
                $deletedCount = 0;
                foreach (array_keys($normalized) as $fileName) {
                    if ($deleteFileFromDisk($fileName)) {
                        $deletedCount++;
                    }
                }

                if ($deletedCount > 0) {
                    $messages[] = sprintf('Deleted %d file%s.', $deletedCount, $deletedCount === 1 ? '' : 's');
                }
            }
        }
    }
}

$rawFiles = [];
if (is_dir($uploadsDir)) {
    $scan = scandir($uploadsDir);
    foreach ($scan as $file) {
        if ($file === '.' || $file === '..') {
            continue;
        }

        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        if (!in_array($extension, $allowedExtensions, true)) {
            continue;
        }

        $rawFiles[] = $file;
    }
}

$files = [];
foreach ($rawFiles as $file) {
    $filePath = $uploadsDir . DIRECTORY_SEPARATOR . $file;
    if (!is_file($filePath)) {
        continue;
    }

    $firstSeenValue = $imageLog[$file]['first_seen'] ?? null;
    if ($firstSeenValue === null) {
        $firstSeenTimestamp = filemtime($filePath) ?: $now;
        $imageLog[$file] = ['first_seen' => date('c', $firstSeenTimestamp)];
        $logChanged = true;
    } else {
        if (is_numeric($firstSeenValue)) {
            $firstSeenTimestamp = (int) $firstSeenValue;
        } else {
            $parsedTime = strtotime((string) $firstSeenValue);
            $firstSeenTimestamp = $parsedTime ?: $now;
        }
    }

    $ageSeconds = max(0, $now - $firstSeenTimestamp);
    $remainingSeconds = max(0, $expireSeconds - $ageSeconds);
    $expiresAt = $firstSeenTimestamp + $expireSeconds;
    $daysLeft = (int) ceil($remainingSeconds / 86400);
    $sizeBytes = filesize($filePath) ?: 0;

    $files[] = [
        'name' => $file,
        'url' => 'uploads/' . rawurlencode($file),
        'first_seen' => $firstSeenTimestamp,
        'expires_at' => $expiresAt,
        'days_left' => $daysLeft,
        'size' => $sizeBytes,
        'size_label' => $formatBytes((int) $sizeBytes),
    ];
}

if ($files) {
    usort($files, static function ($a, $b) {
        return $a['expires_at'] <=> $b['expires_at'];
    });
}

foreach (array_keys($imageLog) as $loggedFile) {
    if (!in_array($loggedFile, $rawFiles, true)) {
        unset($imageLog[$loggedFile]);
        $logChanged = true;
    }
}

if ($logChanged) {
    file_put_contents($logFile, json_encode($imageLog, JSON_PRETTY_PRINT));
}

?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Uploaded Files</title>
    <link rel="stylesheet" href="style.css">
</head>
<body class="files-page">
<div class="panel file-panel">
    <div class="panel-header">
        <h1>Uploaded Files</h1>
        <p>Images stay live for <?php echo (int) $expireDays; ?> day(s). Delete them manually at any time.</p>
    </div>

    <?php if ($messages || $errors): ?>
        <div class="messages">
            <?php foreach ($messages as $message): ?>
                <div class="alert success"><?php echo htmlspecialchars($message, ENT_QUOTES); ?></div>
            <?php endforeach; ?>
            <?php foreach ($errors as $error): ?>
                <div class="alert error"><?php echo htmlspecialchars($error, ENT_QUOTES); ?></div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <?php if ($files): ?>
        <div class="file-grid">
            <?php foreach ($files as $file): ?>
                <article class="file-card<?php echo $file['days_left'] <= 1 ? ' expiring' : ''; ?>">
                    <label class="file-select">
                        <input form="bulkDeleteForm" type="checkbox" name="selected_files[]" value="<?php echo htmlspecialchars($file['name'], ENT_QUOTES); ?>">
                        <span class="checkbox"></span>
                    </label>
                    <div class="file-preview">
                        <img src="<?php echo htmlspecialchars($file['url'], ENT_QUOTES); ?>" alt="<?php echo htmlspecialchars($file['name'], ENT_QUOTES); ?>">
                    </div>
                    <div class="file-meta">
                        <div class="file-name"><?php echo htmlspecialchars($file['name'], ENT_QUOTES); ?></div>
                        <div class="file-stats">
                            <span class="badge"><?php echo max(0, $file['days_left']); ?> day<?php echo $file['days_left'] === 1 ? '' : 's'; ?> left</span>
                            <span>Expires <?php echo date('M j, Y', $file['expires_at']); ?></span>
                            <span>First seen <?php echo date('M j, Y', $file['first_seen']); ?></span>
                            <span><?php echo htmlspecialchars($file['size_label'], ENT_QUOTES); ?></span>
                        </div>
                    </div>
                    <form method="post" class="file-actions" onsubmit="return confirm(<?php echo htmlspecialchars(json_encode('Delete ' . $file['name'] . '?'), ENT_QUOTES); ?>);">
                        <input type="hidden" name="delete_file" value="<?php echo htmlspecialchars($file['name'], ENT_QUOTES); ?>">
                        <button type="submit" class="danger-button">Delete</button>
                    </form>
                </article>
            <?php endforeach; ?>
        </div>
        <form method="post" id="bulkDeleteForm" class="bulk-actions">
            <input type="hidden" name="delete_selected" value="1">
            <button type="submit" id="bulkDeleteButton" class="danger-button" disabled>Delete selected</button>
        </form>
    <?php else: ?>
        <div class="empty-files">
            <p>No uploaded files were found.</p>
            <a href="upload.php">Upload your first meme</a>
        </div>
    <?php endif; ?>

    <div class="links">
        <?php echo meme_auth_user_link(); ?>
        <a href="upload.php">Upload another meme</a>
        <a href="index.php">Open slideshow</a>
    </div>
</div>
<?php if ($files): ?>
<script>
    const bulkButton = document.getElementById('bulkDeleteButton');
    const bulkCheckboxes = document.querySelectorAll('#bulkDeleteForm input[type="checkbox"], .file-select input[type="checkbox"]');

    function updateBulkButton() {
        if (!bulkButton) {
            return;
        }
        const selectedCount = Array.from(bulkCheckboxes).filter(cb => cb.checked).length;
        bulkButton.disabled = selectedCount === 0;
        bulkButton.textContent = selectedCount
            ? `Delete ${selectedCount} selected`
            : 'Delete selected';
    }

    bulkCheckboxes.forEach(cb => cb.addEventListener('change', updateBulkButton));
    updateBulkButton();
</script>
<?php endif; ?>
</body>
</html>
