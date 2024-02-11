<?php
$data=mysqli_connect("localhost","root","","crud");
$delete=$_GET['delete'];

$sql ="delete from users where id = '$delete'";

if(mysqli_query($data,$sql))
        {
            echo '<script> location.replace("application.php")</script>';
        }
        else
        {
        echo "Something went wrong!" . $data->error;
        }


?>