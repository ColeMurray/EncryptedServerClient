#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

void cleanUpOpenSSL(){
	ENGINE_cleanup();
	CONF_modules_unload(1);
	ERR_remove_state(0);
	ERR_free_strings();
	EVP_cleanup();
	sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
	CRYPTO_cleanup_all_ex_data();
	
}

BIO * waitAndAcceptConnection(char* portnum){
	BIO *connection;
	connection = BIO_new_accept(portnum); 

	if (connection == NULL){
		printf ("Error setting up connection\n");
	}
	/* setup comm_fd */
	if(BIO_do_accept(connection) <=0){
		printf ("Error setting up comm_fd  \n");
		BIO_free_all(connection);
		cleanUpOpenSSL();	
		exit (0);
	}	
	
	if (BIO_do_accept(connection) <=0){
		printf ( "Error accepting connection \n" );
		BIO_free_all(connection);
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
	BIO_free_all(pubFile);
	return rsaPublicKey;
}

RSA* getPrivateKey(){
	BIO *privFile = BIO_new_file("./privkey.pem","r");
	RSA *rsaPrivKey = PEM_read_bio_RSAPrivateKey (privFile,NULL,NULL,NULL);
	int rsaSize = RSA_size(rsaPrivKey);
	BIO_free_all(privFile);
	return rsaPrivKey;	
}


unsigned char* getChallengeFromClient(BIO* connection){
	RSA *rsaPublicKey = getPublicKey();
	int rsaSize = RSA_size(rsaPublicKey);
	printf ("Read keysize of : %d \n", rsaSize);
	int bytesReceived;
	unsigned char recvBuf[rsaSize];

	bytesReceived = BIO_read(connection,recvBuf,sizeof recvBuf );
	if (bytesReceived <= 0 ){
		printf ("Error receiving challenge \n" );
		exit(0);
	}
	printf ("Recieved encrypted challenge of size: %d \n", bytesReceived);
	printf ("Preparing to decrypt \n");
	RSA* rsaPrivKey = getPrivateKey();
	int rsaPrivSize = RSA_size(rsaPrivKey);
	
	unsigned char* decRecvBuf = (unsigned char*) malloc (rsaSize);
	RSA_private_decrypt(bytesReceived, recvBuf,
			  decRecvBuf, rsaPrivKey,RSA_PKCS1_PADDING);

	printf ("Decrypted challenge: %s \n", decRecvBuf );

	RSA_free(rsaPrivKey);
	RSA_free(rsaPublicKey);
	return decRecvBuf;
}

unsigned char* hashChallenge(const unsigned char* challenge ){

	// SHA-1 encryption on hash
	// sign with private key
	// send to client
//	unsigned char*  shaOutput = (unsigned char*) malloc(20+1); // SHA hashes to 20 bits
	printf ("STRLEN: %lu, SizeOf: %lu \n ", strlen(challenge), sizeof challenge);
	
	unsigned char* shaOutput = (unsigned char*) malloc (20 +1);
	SHA1(challenge,strlen(challenge),shaOutput);
	return shaOutput;	
}

unsigned char* signChar (const unsigned char* challenge, int challengeLength,
						 int* encryptLength){
	RSA *privateKey = getPrivateKey();
	int keySize = RSA_size(privateKey);
	unsigned char* output = (unsigned char*) malloc (keySize);
	
	int sizeEncrypted = RSA_private_encrypt( challengeLength, challenge,
						output, privateKey,
						RSA_PKCS1_PADDING);
	*encryptLength = sizeEncrypted; 

	if (sizeEncrypted <=0){
		printf ("Error encrypting hashed message");
		exit(0);
	}

	return output;
	


}
void sendToClient(BIO* bio, unsigned char* message, int mLength ){
	if (BIO_write(bio,message, mLength) <= 0){
		printf( "Error sending to client \n");
		exit(1);
	}
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
	const unsigned char* challenge = getChallengeFromClient(connection);
	unsigned char* hashedChallenge = hashChallenge(challenge);
	int *signedHashLength = (int*) malloc (sizeof(int));
	
	// returns signed hash and assigns length to signedHashLength
	unsigned char* signedHash = signChar(
					hashedChallenge,
					strlen(hashedChallenge),
					signedHashLength); 
	sendToClient(connection,signedHash,*signedHashLength);
	BIO_free_all(connection);
	free((unsigned char*)challenge);
	free(hashedChallenge);
	free(signedHash);	
	cleanUpOpenSSL();		
	return 0;
}

