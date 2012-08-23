<?php
/**
 * CodeIgniter Angel.co API Library (http://thinkoverit.com)
 * 
 * Author: Pandurang Zambare, pandu@thinkoverit.com
 * 
 * This is Conteller Class for Codeigniter Framework.
 **/
class angel extends Controller 
{
	function angel()
	{
		parent::Controller();
		session_start();
		$this->load->library('angelco');
	}
	function index()
	{

		if(!$this->angelco->logged_in()){
			$this->angelco->login();
			return;
		}else {
			echo "Thank You! You're logged in via AngelList.";
			
			//$userObj = $this->angelco->call('get', 'me');
			//$userFounded = $this->angelco->call('get', 'startup_roles?user_id='.$userObj->id);
		}
	}
}


?>