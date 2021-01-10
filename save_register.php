<?php
session_start();
require 'functions.php';

$email = $_POST['email'];
$password = $_POST['password'];

$user_email = get_user_by_email($email);
if (!empty($user_email)) {
    set_flash_message('danger', "Этот эл. адрес уже занят другим пользователем.");
    redirect_to('page_register.php');
    exit();
}

add_user($email, $password);
set_flash_message('success', "Регистрация успешна");
redirect_to('page_login.php');