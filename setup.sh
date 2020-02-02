#!/bin/bash 

[[ `id -u` == '0' ]] && 'please, start the script as regular user' && exit 1 
user=`whoami` 
sudo groupadd -g 666 keepsecret 
sudo gpasswd -a $user keepsecret 
sudo mkdir /etc/keepsecret
sudo touch /etc/keepsecret/shadow
sudo chmod 0660 /etc/keepsecret/shadow
sudo chown root:keepsecret /etc/keepsecret/shadow 

sudo cp keepsecret.py /usr/local/bin/keepsecret.py
sudo chown root:keepsecret /usr/local/bin/keepsecret.py
sudo chmod +x /usr/local/bin/keepsecret.py
sudo ln -s /usr/local/bin/keepsecret.py /bin/keepsecret

. /etc/os-release
[[ "$ID_LIKE" == "debian" ]] && sudo apt update && sudo apt install -y python3-pip 

pip3 install cryptography

sudo -k
echo "Warning , you only be able to use keepsecret after new login"
