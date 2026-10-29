<?php
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $id);
echo "Hello " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
$hash = password_hash($_POST['password'], PASSWORD_DEFAULT);
