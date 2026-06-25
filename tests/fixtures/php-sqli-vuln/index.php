<?php
// Deliberately vulnerable: unsanitized $_GET flows into a raw SQL query.
function list_user($conn) {
    $id = $_GET['id'];
    $sql = "SELECT * FROM users WHERE id = " . $id;
    return mysqli_query($conn, $sql);
}

$conn = mysqli_connect("localhost", "app", "secret", "appdb");
$rows = list_user($conn);
