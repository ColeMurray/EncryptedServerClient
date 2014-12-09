#EncryptedServerClient
=====================

###OpenSSL Encrypted File Server Client

Usage: <br>./client --serveraddress=00.11.22.33.44 --portnum=1234 --send ./file    (send file to server) <br>
       ./client --serveraddress=00.11.22.33.44 --portnum=1234 --receive ./file    (receive file from server)

       ./server --portnum=1234
       


#####*Milestone 1*: **COMPLETE**

######**Server**

 ```~~hash challenge using sha-1~~```

  ```~~sign hash with private key~~```

  ```~~send encrypted hash~~```

######_*Client*_

  ```-decrypt hash with public key of server```

  ```-confirm match with sent challenge```
  
  ```-terminate if no match```

  ```-proceed to send request```


#####*Milestone 2*: **COMPLETE**
######-Server
    ~~process & handle request~~
  
######-Client
       ~~if receive, prepare buffer~~
    

       

