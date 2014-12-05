#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

BIO * waitAndAcceptConnection(char* portnum){
	BIO *connection;
	connection = BIO_new_accept(portnum); 

	/* setup comm_fd */
	if(BIO_do_accept(connection) <=0){
		printf ("Error setting up comm_fd  \n");
		exit (0);
	}	
	
	if (BIO_do_accept(connection) <=0){
		printf ( "Error accepting connection \n" );
		exit(0);
	}
	printf( "Connection Established on port: %s \n", portnum );
	return connection;
}

RSA* getPublicKey (){
	BIO *pubFile = BIO_new_file("./pubkey.pem","r");
	RSA *rsaPublicKey = PEM_read_bio_RSA_PUBKEY(pubFile,NULL,NULL,NULL);
	int rsaSize = RSA_size(rsaPublicKey);
	printf ("Read keysize of : %d \n", rsaSize);
	return rsaPublicKey;
}

RSA* getPrivateKey(){
	BIO *privFile = BIO_new_file("./privkey.pem","r");
	RSA *rsaPrivKey = PEM_read_bio_RSAPrivateKey (privFile,NULL,NULL,NULL);
	int rsaSize = RSA_size(rsaPrivKey);
	return rsaPrivKey;	
}


BIO *keyExchangeWithClient(BIO* connection){
	RSA *rsaPublicKey = getPublicKey();
	int rsaSize = RSA_size(rsaPublicKey);
	printf ("Read keysize of : %d \n", rsaSize);
	int bytesReceived;
	char recvBuf[rsaSize];

	printf ("Malloc'd %d bytes", sizeof (recvBuf) );
	bytesReceived = BIO_read(connection,recvBuf,sizeof recvBuf );
	if (bytesReceived <= 0 ){
		printf ("Error receiving challenge \n" );
		exit(0);
	}
	printf ("Recieved encrypted challenge of size: %d \n", bytesReceived);
	printf ("Preparing to decrypt \n");
	RSA* rsaPrivKey = getPrivateKey();
	int rsaPrivSize = RSA_size(rsaPrivKey);
	
	char decRecvBuf[bytesReceived];
	RSA_private_decrypt(bytesReceived, recvBuf,
			 (unsigned char*)decRecvBuf, rsaPrivKey,RSA_PKCS1_PADDING);
	printf ("Decrypted challenge: %s \n", decRecvBuf );

	
	return connection;
}


int main(int count, char *args[]){

	char* portnum;
	if (count != 2){
		printf("Usage:%s portnum\n",args[0]);
	}
	portnum = args[1];
	
	SSL_library_init();
	

	/* wrapper to tcp's accept function. Will establish a connection
	   will wait for an incoming connection	
	*/
	BIO *connection = waitAndAcceptConnection(portnum);
	connection = keyExchangeWithClient(connection);	
	return 0;
}

