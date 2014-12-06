EncryptedServerClient
=====================

OpenSSL Encrypted File Server Client

*Still in progress*

*Milestone 1*:

_Server_

  -hash challenge using sha-1

  -sign hash with private key

  -send encrypted hash

_*Client*_

  -decrypt hash with public key of server

  -confirm match with sent challenge
    -terminate if no match

  -proceed to send request


*Milestone 2*
-Server
    -process & handle request
  
    -Client
        -if receive, prepare buffer
    



Usage: ./client host port filename

       ./server port
       

