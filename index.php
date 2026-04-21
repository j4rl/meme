<?php
$uploadsDir = __DIR__ . DIRECTORY_SEPARATOR . 'uploads';
$allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
$rawFiles = [];

if (is_dir($uploadsDir)) {
    $dirIterator = scandir($uploadsDir);
    foreach ($dirIterator as $file) {
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

$settingsFile = __DIR__ . DIRECTORY_SEPARATOR . 'settings.json';
$intervalSeconds = 5;
$expireDays = 300;
$randomizeOrder = false;

if (is_file($settingsFile)) {
    $settings = json_decode((string) file_get_contents($settingsFile), true);
    if (is_array($settings)) {
        if (isset($settings['interval']) && is_numeric($settings['interval'])) {
            $intervalSeconds = max(1, (int) $settings['interval']);
        }

        if (isset($settings['expire_days']) && is_numeric($settings['expire_days'])) {
            $expireDays = max(1, (int) $settings['expire_days']);
        }

        if (isset($settings['randomize_order'])) {
            $randomizeOrder = (bool) $settings['randomize_order'];
        }
    }
}

$expireSeconds = $expireDays * 86400;
$logFile = __DIR__ . DIRECTORY_SEPARATOR . 'image_log.json';
$imageLog = [];

if (is_file($logFile)) {
    $decodedLog = json_decode((string) file_get_contents($logFile), true);
    if (is_array($decodedLog)) {
        $imageLog = $decodedLog;
    }
}

$images = [];
$now = time();
$logChanged = false;

foreach ($rawFiles as $file) {
    $firstSeenValue = $imageLog[$file]['first_seen'] ?? null;
    if ($firstSeenValue === null) {
        $imageLog[$file] = ['first_seen' => date('c', $now)];
        $firstSeenTimestamp = $now;
        $logChanged = true;
    } else {
        if (is_numeric($firstSeenValue)) {
            $firstSeenTimestamp = (int) $firstSeenValue;
        } else {
            $firstSeenTimestamp = strtotime((string) $firstSeenValue) ?: $now;
        }
    }

    if (($now - $firstSeenTimestamp) >= $expireSeconds) {
        $filePath = $uploadsDir . DIRECTORY_SEPARATOR . $file;
        if (is_file($filePath)) {
            @unlink($filePath);
        }
        unset($imageLog[$file]);
        $logChanged = true;
        continue;
    }

    $images[] = [
        'file' => $file,
        'url' => 'uploads/' . rawurlencode($file),
    ];
}

if ($images) {
    if ($randomizeOrder) {
        shuffle($images);
    } else {
        usort($images, static function ($a, $b) {
            return strnatcasecmp($a['file'], $b['file']);
        });
    }
}

$activeFilesLookup = array_fill_keys(array_column($images, 'file'), true);
foreach ($imageLog as $file => $meta) {
    if (isset($activeFilesLookup[$file])) {
        continue;
    }

    $fullPath = $uploadsDir . DIRECTORY_SEPARATOR . $file;
    if (!is_file($fullPath)) {
        unset($imageLog[$file]);
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
    <title>Memer Gallery</title>
    <link rel="stylesheet" href="style.css">
</head>
<body class="viewer-page">
<div class="viewer">
    <?php if ($images): ?>
        <img id="viewerImage" src="<?php echo htmlspecialchars($images[0]['url'], ENT_QUOTES); ?>" alt="Uploaded meme">
    <?php else: ?>
        <div class="empty">
            Drop your first meme via the upload page to start the slideshow.
            <a href="upload.php">Go to upload page</a>
        </div>
    <?php endif; ?>
</div>

<?php if ($images): ?>
<script>
    const images = <?php echo json_encode(array_column($images, 'url'), JSON_UNESCAPED_SLASHES); ?>;
    const intervalMs = <?php echo (int) $intervalSeconds * 1000; ?>;
    const viewerImage = document.getElementById('viewerImage');

    let currentIndex = 0;

    function render(index) {
        currentIndex = index;
        viewerImage.src = images[currentIndex];
    }

    function next() {
        const newIndex = (currentIndex + 1) % images.length;
        if (newIndex === 0) {
            window.location.reload();
            return;
        }
        render(newIndex);
    }

    setInterval(next, intervalMs);
</script>
<?php endif; ?>
</body>
</html>
