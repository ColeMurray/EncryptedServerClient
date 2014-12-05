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

	bio = BIO_new_ssl_connect(ctx);
	if (bio == NULL ){
		printf("Error setting up bio \n");
		exit(0);
	}

	
	BIO_get_ssl (bio, &ssl);

	if (!ssl){
		printf( "can't locat sslpointer \n" );
	}
	// set read/write operations to only return after the handshake
	// and successful completion
	SSL_set_mode(ssl,SSL_MODE_AUTO_RETRY);
	
	//bio = BIO_new_connect ("127.0.0.1:5555"); //set ipaddress:port
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
	unsigned char *rsaSizeBuf = (unsigned char * ) malloc (maxSize);
}
unsigned char* encryptChallenge (char *challenge){
	BIO *keyFile = BIO_new_file("./pubkey.pem", "r" );
	if (keyFile == NULL){
		printf ( "Error with bio object in encrypt");
	}
	RSA *rsa_public_key = RSA_new();
        rsa_public_key = PEM_read_bio_RSA_PUBKEY(keyFile, NULL,NULL,NULL);
	if (rsa_public_key == NULL)
	{
		printf( "Error wit public key" );
		exit(0);
	}

	int pubSize = RSA_size(rsa_public_key);	

	unsigned char * output = allocateOutputBuf( rsa_public_key );

	// encrypt challenge with public key, loads into outputBuffer
	// challengeLen must be < RSA_size(rsa_ -11 for RSA_PKCS1_Padding

	if (RSA_public_encrypt(strlen(challenge),(unsigned char*) challenge, output, rsa_public_key,
					RSA_PKCS1_PADDING) < 0 ) {
		printf ("Error encrypting challenge");
		exit(0);
	}
	return output;


}


void sendToServer ( BIO* bio, unsigned char *message){
	if(BIO_write ( bio, message, strlen (message)) <= 0 ){
		printf ("Error writing to server");
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
	OpenSSL_add_all_algorithms();
	hostname = args[1];
	portnum = args[2];
	filename = args[3];


	char *formattedServerPort = formatServerPort(hostname,portnum);

	BIO * serverConnection = connectSSL(ctx,formattedServerPort);

	unsigned char *challenge = "Very Long string lol";
	unsigned char* encryptedChallenge = encryptChallenge(challenge);
	// Send Challenge to server
	sendToServer (serverConnection,encryptedChallenge );

	
	return 0;
}
	
