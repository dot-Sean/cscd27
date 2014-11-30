<?php
$username = addslashes($_POST['username']);  # username field from POST'ed HTML form
$sql = "SELECT * FROM Person WHERE Username = '$username' ";
$query = $db->prepare($sql);
$rs = $db->executeQuery($query);
?>
