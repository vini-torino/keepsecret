#!/bin/bash 

[[ `id -u` == '0' ]] && 'please, start the script as regular user' && exit 1 
user=`whoami` 
sudo groupadd keepsecret 
sudo gpasswd -a $user keepsecret 
sudo mkdir /etc/keepsecret
sudo touch /etc/keepsecret/shadow
sudo chmod 0660 /etc/keepsecret/shadow
sudo chown root:keepsecret /etc/keepsecret/shadow 

sudo cp keepsecret.py /usr/local/bin/keepsecret.py
sudo chown root:keepsecret /usr/local/bin/keepsecret.py
sudo chmod +x /usr/local/bin/keepsecret.py
sudo ln -s /usr/local/bin/keepsecret.py /bin/keepsecret
sudo -k
echo "Warning , you only be able to use keepsecret after new login"
