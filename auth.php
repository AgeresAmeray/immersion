<?php
session_start();
require 'functions.php';

$email = $_POST['email'];
$password = $_POST['password'];

$login = login($email, $password);
if (!empty($login)) {
    redirect_to('page_users.php');
    exit();
}
redirect_to('page_login.php');