This is a quick run down of what this machine does and how to work with it.


1) The Machine
The username and password for the root user "ssas" is "ssas", which might not be a very good password.


2) Webserver
The webserver runs autimatically on startup, and can be accessed by the IP address (which can be found with "ifconfig"), or as "localhost" on port 80. 
The code for the webserver is located in "/var/www/html".


3) MySQL Database
The MySQL database runs automatically, and the webserer already has the followint credentials embedded in it:

username: "root"
password: "ssas"

The database can be reset by running "mysql -u root -p < datamodel.sql", the file for which can be found in "/var/www/html".
