<?php
session_start();

require 'configDB.php';


function get_user_by_email($email)
{
    global $pdo;
    $statemant = $pdo->prepare("SELECT * FROM users WHERE email=:email");
    $statemant->execute(['email' => $email]);
    $user = $statemant->fetch(PDO::FETCH_ASSOC);
    return $user;
}

function add_user($email, $password)
{
    global $pdo;
    $password = password_hash($password, PASSWORD_DEFAULT);
    $statemant = $pdo->prepare("INSERT INTO users (email, password) VALUES (:email, :password)");
    $statemant->execute(
        [
            'email' => $email,
            'password' => $password
        ]
    );
}

function set_flash_message($name, $message)
{
    $_SESSION[$name] = $message;
}

function display_flash_message($name)
{
    if (isset($_SESSION[$name])) {
        echo "<div class='alert alert-{$name}'>$_SESSION[$name]</div>";
        unset($_SESSION[$name]);
    }
}

function redirect_to($path)
{
    header("Location: $path");
}

function login($email, $password)
{

    $user = get_user_by_email($email);

    if (!empty($user) && password_verify($password, $user['password'])) {
        $_SESSION['id'] = $user['id'];
        $_SESSION['status'] = $user['is_admin'];
        if ($_SESSION['status'] == 1) {
            return true;
        }
        return true;
    }
    set_flash_message('danger', 'Неверный логин или пароль');
    return false;
}

function get_all_user()
{
    global $pdo;

    $statemant = $pdo->prepare("SELECT * FROM users");
    $statemant->execute();
    $users = $statemant->fetchAll(PDO::FETCH_ASSOC);
    return $users;
}







