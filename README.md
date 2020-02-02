# Keepsecret

keepsecret script is a simple way to encrypted files using shadow like passwords

Usage:

	keepsecret -n target_file
		Set new shadow password and encrypt target_file.

	keepsecret -d target_file
		Decrypt target_file file asking your password.

	keepsecret -e target_file
		Encrypt everything all over again.


Warning:

	Once you encrypt a file, it only possible to retrive it using the same password.
	Take care while changing Keepsecret's password, you could loose data.
	If you really need to do so, better decrypt all your secret files first,
	and then encrypted everything again using the new password.

	Also, you must be in the keepsecret group in order to use this utility.
	Please, read setup.sh for more details. 
