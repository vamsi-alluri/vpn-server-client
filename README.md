# vpn-server-client

Instructions to run:

1.	Running the VPN:
    1. cd /to_directory_of_files
	  1. gcc -o simpletun simpletun.c -lssl -lcrypt on both machines
1.	Setting up the tunnels:
    1. sudo ./config_vm# {Use the commands in the config file.}
1.	Play around, have a good day!



This code is based on Davide Brini's Tun/TAP TCP implementation, I've implemented it on UDP with OPEN SSL for sessions, AES for encryption and SHA-256 Hash algorithm for HMAC.
