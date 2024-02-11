<?php
session_start();
if(!isset($_SESSION["name"])){
    header("location:login.php");
}

require __DIR__ . '/../views/adminhome.view.php';
$data=mysqli_connect("localhost","root","","crud");

?>