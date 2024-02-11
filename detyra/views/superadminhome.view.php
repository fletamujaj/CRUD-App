<!DOCTYPE html>
<html>
<head>
    <style>
        .container {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100vh; 
        }

        h1 {
            font-family: Arial, sans-serif;
            font-size: 36px;
            color: #333;
        }

        .btn {
            width: 200px;
            height: 60px;
            margin: 10px;
            border: none;
            border-radius: 10px;
            font-family: Arial, sans-serif;
            font-size: 24px;
            font-weight: bold;
            color: #fff;
            cursor: pointer;
        }
        .btn-green {
            background-color: #4CAF50;
        }

        .btn-red {
            background-color: #F44336;
        }
    </style>
</head>
<body>
    <div class="container">
    <h1> <?php echo "Hello SuperAdmin ". $_SESSION["name"] ?></h1>
        <h1> Where to? </h1>
        <button class="btn btn-green"> <a href="http://localhost/detyra/userProfile.php">Profile</button>
        <button class="btn btn-success"> <a href='http://localhost/detyra/crud/application.php'> App </a></button>
        <button class="btn btn-red"> <a href="http://localhost/detyra/logout.php">Logout</a> </button>
    </div>
</body>
</html>