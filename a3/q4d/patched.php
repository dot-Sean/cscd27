<?php
$username = addslashes($_POST['username']);  # username field from POST'ed HTML form
$sql = "SELECT * FROM Person WHERE Username = ?";
$query = $db->prepareStatement($sql);
$query.setString(1, $username);
$rs = $query->executeQuery();
?>
