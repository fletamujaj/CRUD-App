<?php
    session_start();
    $data=mysqli_connect("localhost","root","","crud");
    if($data==false)
    {
        die("connection error!");
    }

    if(isset($_POST['sumbit']))
    {
        $name= $_POST['name'];
        $address=$_POST['address'];
        $mobile=$_POST['mobile'];
        $role=$_POST['role'];
        $debt=$_POST['debt'];

        $sql = "insert into users(name,address,mobile,role,debt)values('$name','$address','$mobile','$role',$debt)";

        if(mysqli_query($data,$sql))
        {
            echo '<script> location.replace("application.php")</script>';
        }
        else
        {
        echo "Something went wrong!" . $data->error;
        }
    }
?>

<!DOCTYPE html>s
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>CRUD Application </title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">
    <style>
        .mt40{
            margin-top: 40px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="row">
            <div class="col-mid-9">
            <div class="card">
            <div class="card-header">
               <h1> CRUD Application </h1>
            </div>
            <div class="card-body">
            <form action="add.php" method="POST">
                <div class="form-group">
                    <label for="exampleInputEmail1"> Name </label>
                    <input type="text" name="name" class="form-control"  placeholder="Enter Name">
                </div>

                <div class="form-group">
                    <label for="exampleInputEmail1"> Address </label>
                    <input type="text"name="address" class="form-control"  placeholder="Enter Address">
                </div>

                <div class="form-group">
                    <label for="exampleInputEmail1"> Mobile </label>
                    <input type="text" name="mobile" class="form-control"  placeholder="Enter Mobile">
                </div>

                <div class="form-group">
                    <label for="exampleInputEmail1"> Role </label>
                    <input type="text" name="role" class="form-control"  placeholder="Enter Role">
                </div>
                <div class="form-group">
                    <label for="exampleInputEmail1"> Debt </label>
                    <input type="text" name="debt" class="form-control"  placeholder="Enter Debt">
                </div>
                <br/>
                <input type="submit" class="btn btn-primary" name="sumbit" value="Register">
                </form>

            </div>
            </div>
            

            </div>

        </div>
    </div>

</body>
</html>

