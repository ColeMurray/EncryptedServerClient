#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
SSL_CTX*  initCTX(){
	SSL_CTX *ctx;
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	ctx = SSL_CTX_new( SSLv23_client_method()); //create new context
	
	if ( ctx == NULL ){
		printf ("Error with context");
		abort();
	}

	SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL); //set ctx to ignore certificates

	return ctx;

}

BIO* connectSSL(SSL_CTX *ctx, char *formattedServPort){
	BIO *bio;
	SSL *ssl;
/*
	bio = BIO_new_ssl_connect(ctx);
	if (bio == NULL ){
		BIO_free_all(bio);
		SSL_CTX_free(ctx);
		printf("Error setting up bio \n");
		exit(0);
	}
*/
	
/*	BIO_get_ssl (bio, &ssl);

	if (!ssl){
		BIO_free_all(bio);
		SSL_CTX_free(ctx);
		printf( "can't locat sslpointer \n" );
		exit(0);
	} */
	// set read/write operations to only return after the handshake
	// and successful completion
//	SSL_set_mode(ssl,SSL_MODE_AUTO_RETRY);
	//BIO_set_conn_hostname(bio,formattedServPort);

	bio = BIO_new_connect (formattedServPort);
	
	/* attempts connection */
	if (BIO_do_connect (bio) <= 0 ){
		printf("ERROR \n");
		BIO_free_all(bio);
		SSL_CTX_free(ctx);
		exit(1);
	}
	printf( "Connected to client \n" );
	
	if (BIO_do_handshake(bio) <= 0 ){
		fprintf (stderr, "Error in handshake \n ");
		exit(1);
	}

	printf ( "Completed handshake! \n" );
	return bio;
}

unsigned char * allocateOutputBuf (RSA *rsa_public_key){
	int maxSize = RSA_size(rsa_public_key);
	printf ("Max size is : %d \n" ,maxSize);
	unsigned char *rsaSizeBuf = (unsigned char * ) malloc (maxSize+1);
	return rsaSizeBuf;
}
unsigned char* encryptChallenge (unsigned char *challenge, int* messageLength){
	BIO *keyFile = BIO_new_file("./pubkey.pem", "r" );
	if (keyFile == NULL){
		printf ( "Error with bio object in encrypt");
	}
	RSA *rsa_public_key = PEM_read_bio_RSA_PUBKEY(keyFile, NULL,NULL,NULL);
	if (rsa_public_key == NULL)
	{
		printf( "Error wit public key" );
		exit(0);
	}


	unsigned char * output = allocateOutputBuf( rsa_public_key );

	// encrypt challenge with public key, loads into outputBuffer
	// challengeLen must be < RSA_size(rsa_ -11 for RSA_PKCS1_Padding
	printf ("Challenge is size of: %lu \n", strlen(challenge));
	int sizeEncrypted = RSA_public_encrypt(strlen(challenge),
			      (unsigned char*) challenge,
			      output, rsa_public_key,
			      RSA_PKCS1_PADDING);
	if (sizeEncrypted <= 0 ) {
		printf ("Error encrypting challenge");
		exit(0);
	}
	*messageLength = sizeEncrypted;
	RSA_free(rsa_public_key);
	BIO_free_all(keyFile);
	return output;
}


void sendToServer ( BIO* bio, unsigned char *message, int* messageLength){
	printf("Writing message:size: %d \n",*messageLength);
	if(BIO_write ( bio, message, *messageLength) <= 0 ){
		printf ("Error writing to server");
	}

}

int compareHashFromServer (BIO* bio, unsigned char* challenge){
	unsigned char recvBuf[20]; //SHA-1 20 bits
	unsigned char hashedChallenge[20];
	
	printf("Challenge is size: %lu, reading : %s \n",strlen(challenge),challenge);
	//Hash the challenge
	SHA1((const unsigned char*)challenge,strlen(challenge),hashedChallenge);
	int bytesReceived = 0;

	bytesReceived = BIO_read(bio,recvBuf,sizeof recvBuf);
	if (bytesReceived <= 0 ){
		printf ( "Error reading hashed challenge" );
		exit(0);
	}
	printf ("read from server: %d bytes \n", bytesReceived);

	if (memcmp( hashedChallenge, recvBuf, sizeof recvBuf ) == 0){
		printf ( "Congrats they match \n ");
		return 1;
	}
	


}	
char* formatServerPort(char *hostname, char *portnum ){
	char *formattedServerPort =  (char*) malloc (strlen(hostname) + strlen(portnum) + 2); // \0' and :
	strcpy (formattedServerPort, hostname);
	strcat (formattedServerPort, ":");
	strcat (formattedServerPort,portnum);
	printf ("%s \n", formattedServerPort );

	return formattedServerPort;
}
		
int main (int count, char *args[]){
	SSL_CTX *ctx;
	char *hostname, *portnum, *filename, *keyfilename;
	SSL_library_init();
	ctx = initCTX();
	if ( count != 4 ){
		printf("usage: %s <hostname> <portname> filename\n ", args[0]);
		exit(0);
	}
	
	//initialize SSL library
//	OpenSSL_add_all_algorithms();
	hostname = args[1];
	portnum = args[2];
	filename = args[3];


	char *formattedServerPort = formatServerPort(hostname,portnum);

	BIO * serverConnection = connectSSL(ctx,formattedServerPort);
	
	int* messageLength = (int*) malloc (sizeof (int));
	unsigned char *challenge = "Random Challenge";
	unsigned char* encryptedChallenge = encryptChallenge(challenge, messageLength);
	printf("Message Length: %d \n",*messageLength);	
	// Send Challenge to server
	sendToServer (serverConnection,encryptedChallenge, messageLength );
	// Receive hash from server
	compareHashFromServer(serverConnection, challenge);

	
	free(encryptedChallenge);
	free (messageLength);		
	BIO_free_all(serverConnection);		
	free(formattedServerPort);
	SSL_CTX_free(ctx);
	EVP_cleanup();
	sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
	CRYPTO_cleanup_all_ex_data();
	return 0;
}
	
