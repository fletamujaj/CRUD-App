<?php
session_start();
$data=mysqli_connect("localhost","root","","crud");

if($data==false)
{
    die("connection error!");
}


if($_SERVER["REQUEST_METHOD"]=="POST"){
    
    $name=$_POST["name"];
    $password=$_POST["password"];

    $sql="select * from users where `name`='$name' AND `password`='$password'";

    $result=mysqli_query($data,$sql);
    $row=mysqli_fetch_array($result);

    $role=$row['role'];
    if($row["role"]=="user"){

        $_SESSION["name"] = $name;
        header("location:http://localhost/detyra/controllers/userhome.controller.php");
    }

    else if($row["role"]=="admin"){

        $_SESSION["name"]=$name;
        header("location:http://localhost/detyra/controllers/adminhome.controller.php");
    }

    else if  ($row["role"]=="superadmin"){

        $_SESSION["name"]=$name;
        header("location:http://localhost/detyra/controllers/superadminhome.controller.php");
    }
    else echo "user not found! ";

    
}
require "views/login.view.php";
?>