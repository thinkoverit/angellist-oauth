<?php
/**
 * Angellist Login
 *
 */
	include_once("angelco.php");

	$obj = new Angelco;
	
	if(!$obj->angelco->logged_in()){
		$obj->angelco->login();
		return;
	}else {
		echo "Thank You! You're logged in via AngelList.";
		$userObj = $obj->angelco->call('get', 'me');
	}


?>