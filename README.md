# P2PServer-ClientWithSSL

environment:
ubuntu 16.04

compile: 

1. open terminal
2. cd to the file
3. make

execute:

4. ./server(default port is 8888, ip is 127.0.0.1, please make the port is clear)
5. ./client(please enter the port number of the client server. if executing on multiple terminals on the same computer, please use different ports)

after connection, client will show the certificate of server, and then client can register, login......

Command:
Create account:
"REGISTER@clientname"
Login:
"clientname@portnum"
Check accounts online now:
"LIST"
Payment:
"clientname#money#anotherclient"
// remeber to enter "LIST" first if decide to pay
© 2020 GitHub, Inc.
