<?php
$username = $_POST['username'];  # username field from POST'ed HTML form
$sql = "SELECT * FROM Person WHERE Username = '$username' ";
$rs = $db->executeQuery($sql);
?>
