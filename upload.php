<?php
require_once __DIR__ . DIRECTORY_SEPARATOR . 'auth.php';
meme_auth_require_login('Logga in till uppladdning');

$uploadsDir = __DIR__ . DIRECTORY_SEPARATOR . 'uploads';
$settingsFile = __DIR__ . DIRECTORY_SEPARATOR . 'settings.json';
$allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
$currentInterval = 5;
$currentExpireDays = 300;
$currentRandomize = false;
$messages = [];
$errors = [];

if (!is_dir($uploadsDir)) {
    $errors[] = 'Uploads directory is missing.';
}

if (is_file($settingsFile)) {
    $savedSettings = json_decode((string) file_get_contents($settingsFile), true);
    if (is_array($savedSettings)) {
        if (isset($savedSettings['interval']) && is_numeric($savedSettings['interval'])) {
            $currentInterval = max(1, (int) $savedSettings['interval']);
        }

        if (isset($savedSettings['expire_days']) && is_numeric($savedSettings['expire_days'])) {
            $currentExpireDays = max(1, (int) $savedSettings['expire_days']);
        }

        if (isset($savedSettings['randomize_order'])) {
            $currentRandomize = (bool) $savedSettings['randomize_order'];
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $settingsValid = true;
    $newInterval = filter_input(INPUT_POST, 'interval', FILTER_VALIDATE_INT);
    $newExpireDays = filter_input(INPUT_POST, 'expire_days', FILTER_VALIDATE_INT);
    $newRandomize = isset($_POST['randomize_order']);

    if ($newInterval === false || $newInterval === null) {
        $errors[] = 'Interval must be a number.';
        $settingsValid = false;
    }

    if ($newExpireDays === false || $newExpireDays === null) {
        $errors[] = 'Expiration days must be a number.';
        $settingsValid = false;
    }

    if ($settingsValid) {
        $currentInterval = max(1, min(3600, (int) $newInterval));
        $currentExpireDays = max(1, min(3650, (int) $newExpireDays));
        $currentRandomize = $newRandomize;
        $settingsPayload = json_encode([
            'interval' => $currentInterval,
            'expire_days' => $currentExpireDays,
            'randomize_order' => $currentRandomize,
        ], JSON_PRETTY_PRINT);

        if ($settingsPayload !== false && file_put_contents($settingsFile, $settingsPayload) !== false) {
            $messages[] = sprintf(
                'Settings updated. Interval: %ds, expires after %d days. Randomize: %s.',
                $currentInterval,
                $currentExpireDays,
                $currentRandomize ? 'on' : 'off'
            );
        } else {
            $errors[] = 'Unable to save settings.';
        }
    }

    if (!empty($_FILES['image']['name'])) {
        if (!is_dir($uploadsDir)) {
            $errors[] = 'Uploads directory is missing on the server.';
        } elseif (!is_uploaded_file($_FILES['image']['tmp_name'])) {
            $errors[] = 'Upload failed. Please try again.';
        } else {
            $originalName = basename($_FILES['image']['name']);
            $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

            if (!in_array($extension, $allowedExtensions, true)) {
                $errors[] = 'Only JPG, PNG, GIF, or WEBP files are allowed.';
            } else {
                $finfo = finfo_open(FILEINFO_MIME_TYPE);
                $mimeType = $finfo ? finfo_file($finfo, $_FILES['image']['tmp_name']) : null;
                if ($finfo) {
                    finfo_close($finfo);
                }

                $allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
                if ($mimeType !== null && !in_array($mimeType, $allowedMimeTypes, true)) {
                    $errors[] = 'Unsupported file type.';
                } else {
                    $cleanName = preg_replace('/[^A-Za-z0-9._-]/', '_', $originalName);
                    $targetName = $cleanName ?: ('image_' . time() . '.' . $extension);
                    $targetPath = $uploadsDir . DIRECTORY_SEPARATOR . $targetName;

                    if (file_exists($targetPath)) {
                        $targetName = pathinfo($targetName, PATHINFO_FILENAME) . '_' . uniqid() . '.' . $extension;
                        $targetPath = $uploadsDir . DIRECTORY_SEPARATOR . $targetName;
                    }

                    if (move_uploaded_file($_FILES['image']['tmp_name'], $targetPath)) {
                        $messages[] = 'Image uploaded successfully.';
                    } else {
                        $errors[] = 'Failed to move the uploaded file.';
                    }
                }
            }
        }
    }
}

?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload Memes</title>
    <link rel="stylesheet" href="style.css">
</head>
<body class="upload-page">
<div class="panel">
    <h1>Upload a Meme</h1>
    <p>Drop images into the slideshow and control how fast they rotate.</p>

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

    <form method="post" enctype="multipart/form-data" class="upload-form">
        <div class="input-field">
            <span class="field-label">Image File</span>
            <label for="image" class="file-drop" id="fileDropZone">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                    <path d="M12 5a3 3 0 0 1 3 3v1h1.75A2.25 2.25 0 0 1 19 11.25v6.5A2.25 2.25 0 0 1 16.75 20h-9.5A2.25 2.25 0 0 1 5 17.75v-6.5A2.25 2.25 0 0 1 7.25 9H9V8a3 3 0 0 1 3-3Zm0 1.5A1.5 1.5 0 0 0 10.5 8v1h3V8A1.5 1.5 0 0 0 12 6.5Z"/>
                    <path d="M12 11.25a.75.75 0 0 1 .75.75v2.25H15a.75.75 0 0 1 0 1.5h-2.25V18a.75.75 0 0 1-1.5 0v-2.25H9a.75.75 0 0 1 0-1.5h2.25V12a.75.75 0 0 1 .75-.75Z"/>
                </svg>
                <span class="file-drop-text">Drag &amp; drop or click to browse</span>
                <span class="file-name" id="fileName">No file selected</span>
            </label>
            <input class="sr-only" type="file" id="image" name="image" accept=".jpg,.jpeg,.png,.gif,.webp">
        </div>
        <div class="input-field">
            <label class="field-label" for="interval">Slide Interval (seconds)</label>
            <input type="number" id="interval" name="interval" min="1" max="3600" value="<?php echo (int) $currentInterval; ?>" required>
        </div>
        <div class="input-field">
            <label class="field-label" for="expire_days">Days before auto-delete</label>
            <input type="number" id="expire_days" name="expire_days" min="1" max="3650" value="<?php echo (int) $currentExpireDays; ?>" required>
        </div>
        <div class="input-field">
            <label class="field-label" for="randomize_order">Randomize image order</label>
            <label class="checkbox-row">
                <input type="checkbox" id="randomize_order" name="randomize_order" value="1"<?php echo $currentRandomize ? ' checked' : ''; ?>>
                <span>Shuffle the slideshow each cycle</span>
            </label>
        </div>
        <button type="submit">Save &amp; Upload</button>
    </form>

    <div class="links">
        <?php echo meme_auth_user_link(); ?>
        <a href="files.php">Manage files</a>
        <a href="index.php">Back to Gallery</a>
    </div>
</div>

<script>
    const imageInput = document.getElementById('image');
    const fileNameLabel = document.getElementById('fileName');
    const dropZone = document.getElementById('fileDropZone');

    const updateFileName = files => {
        if (!files || !files.length) {
            fileNameLabel.textContent = 'No file selected';
            return;
        }

        fileNameLabel.textContent = files.length === 1
            ? files[0].name
            : `${files.length} files selected`;
    };

    if (imageInput) {
        imageInput.addEventListener('change', () => updateFileName(imageInput.files));
    }

    if (dropZone) {
        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, event => {
                event.preventDefault();
                event.stopPropagation();
                dropZone.classList.add('dragover');
            });
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, event => {
                event.preventDefault();
                event.stopPropagation();
                dropZone.classList.remove('dragover');
            });
        });

        dropZone.addEventListener('drop', event => {
            const { files } = event.dataTransfer || {};
            if (!files || !files.length) {
                return;
            }

            imageInput.files = files;
            updateFileName(files);
        });
    }
</script>
</body>
</html>
