#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define maxRequestSize 1024

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

RSA * getPrivateKey(){
	BIO *privFile = BIO_new_file("./privkey.pem","r");
	RSA *rsaPrivKey = PEM_read_bio_RSAPrivateKey (privFile,NULL,NULL,NULL);
	BIO_free_all(privFile);
	return rsaPrivKey;
}

RSA* getPublicKey(){
	BIO *pubFile = BIO_new_file("./pubkey.pem","r");
	RSA *rsaPubKey = PEM_read_bio_RSA_PUBKEY(pubFile,NULL,NULL,NULL);
	BIO_free_all(pubFile);
	return rsaPubKey;
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
	printf( "==========Connected to client=============== \n" );
	
	if (BIO_do_handshake(bio) <= 0 ){
		fprintf (stderr, "Error in handshake \n ");
		exit(1);
	}

	printf ( "==========Completed handshake!=============== \n" );
	return bio;
}

unsigned char * allocateOutputBuf (RSA *rsa_public_key){
	int maxSize = RSA_size(rsa_public_key);
	unsigned char *rsaSizeBuf = (unsigned char * ) malloc (maxSize+1);
	return rsaSizeBuf;
}
unsigned char* encryptChallenge (unsigned char *challenge, int* messageLength){
	RSA *rsa_public_key = getPublicKey();
	unsigned char * output = allocateOutputBuf( rsa_public_key );

	// encrypt challenge with public key, loads into outputBuffer
	// challengeLen must be < RSA_size(rsa_ -11 for RSA_PKCS1_Padding
	int sizeEncrypted = RSA_public_encrypt(strlen(challenge)+1,challenge,
			      output, rsa_public_key,
			      RSA_PKCS1_PADDING);
	if (sizeEncrypted <= 0 ) {
		printf ("Error encrypting challenge");
		exit(0);
	}
	*messageLength = sizeEncrypted;
	RSA_free(rsa_public_key);
	return output;
}


void sendToServer ( BIO* bio, unsigned char *message, int messageLength){
	if(BIO_write ( bio, message, messageLength) <= 0 ){
		printf ("Error writing to server");
	}

}


int compareHashFromServer (BIO* bio, unsigned char* challenge){
	RSA* pubKey = getPublicKey();	
	unsigned char recvBuf[RSA_size(pubKey)]; //SHA-1 20 bits
	unsigned char hashedChallenge[20];
	
	//Hash the challenge
	SHA1((const unsigned char*)challenge,strlen(challenge),hashedChallenge);
	int bytesReceived = 0;

	// Read encrypted hash from server
	bytesReceived = BIO_read(bio,recvBuf,sizeof recvBuf +1);
	if (bytesReceived <= 0 ){
		printf ( "Error reading hashed challenge" );
		exit(0);
	}

	unsigned char decHash [20];
	RSA_public_decrypt(bytesReceived,recvBuf,
				decHash,pubKey,RSA_PKCS1_PADDING);

	RSA_free(pubKey);

	if (memcmp( hashedChallenge, decHash, sizeof hashedChallenge ) != 0){
		printf ( "Servers hash did not match, exiting \n");
		BIO_free_all(bio);
		exit(1);
		
	}
	printf ("============Hashes match!=============== \n");
	return 1;	

}	
char* formatServerPort(char *hostname, char *portnum ){
	char *formattedServerPort =  (char*) malloc (strlen(hostname) + strlen(portnum) + 2); // \0' and :
	strcpy (formattedServerPort, hostname);
	strcat (formattedServerPort, ":");
	strcat (formattedServerPort,portnum);
	printf ("%s \n", formattedServerPort );

	return formattedServerPort;
}

int createByteFile (unsigned char *filename, unsigned char *fileInBytes, int filesize){
		FILE * file;
		file = fopen(filename,"w"); //change to w after debug
		fwrite (fileInBytes ,1,filesize,file);
		fclose(file);
		return 1;
}

/* allocates sets fileLen to length of file */

unsigned char *fileToByteArray(const unsigned char* filename, long *fileLen){
		FILE *f1 = fopen (filename, "r");
		fseek(f1,0,SEEK_END);
		long len = ftell(f1);
		rewind(f1);
		
		//allocate mem for whole file
		unsigned char *ret = (unsigned char*) malloc (sizeof(char) * len);
		
		size_t result = fread(ret,1,len,f1);
		*fileLen = len;
		if (result != len){
			printf ("Error reading from file\n");
		}
		
		
		fclose(f1);
		return ret;
}
unsigned char* recvRequestFromServ(BIO *bio, const int recvLen){
	unsigned char *recvBuf = (unsigned char*) malloc(recvLen +1);
	int bytesRecv = 0;
	if ((bytesRecv =BIO_read(bio,recvBuf,recvLen)) <= 0 ){
		printf("Error reading data \n");
	}
	recvBuf[bytesRecv] = '\0';

	return recvBuf;
}
/* receive filename */

unsigned char *buildRecvProtocol (unsigned char* request, unsigned char *filename){
	unsigned char * protocol;
	protocol = (unsigned char*) malloc (strlen(request) + strlen(filename) + 2);
	memcpy (protocol,request, strlen(request));
	strcat (protocol, " ");
	strcat (protocol, filename);
	return protocol;
}
/* Send : receive filename
 * Serv Reply : filesize filename
 * Send : OK
 * Serv reply : [bytes of file]
 * Send : Done
 */
unsigned char * receiveProtocolFromServer (BIO *bio, unsigned char *request, 
										unsigned char *filename){
											
	unsigned char *protocol = buildRecvProtocol(request,filename);
	// :"receive filename"
	sendToServer(bio,protocol,strlen(protocol));
	// receive : "filesize, filename
	unsigned char *recvBuf = recvRequestFromServ(bio,maxRequestSize);
	
	sendToServer(bio,"OK",2);
	free (protocol);
	
	return recvBuf;
											
}

int parseFilesize(unsigned char * protoResponse){
	unsigned char *filesizeArr = strtok (protoResponse, " ");
	int filesize = atoi ((char *) filesizeArr);
	return filesize;
	
}
/* ===============PROTOCOL =================
 * First Send  :  "send filesize filename"
 * First Recv  :  "Ok"                     *
 * Second Send :  " byteArrayOfFile "
 *=========================================*/
 
 /* This function sends corrupted memory for the send command */
int sendProtocolExchangeWithServer (BIO* bio, const unsigned char *request, 
		const unsigned char* filename, unsigned char *fileSize ){
			
		unsigned char *protocol;
		protocol = (unsigned char*) malloc (strlen(request) + 
							  strlen(fileSize) + strlen(filename) + 3);
		memcpy (protocol, request, strlen(request));
		strcat (protocol, " " );
		strcat (protocol, fileSize);
		strcat (protocol, " " );
		strcat (protocol, filename);
		sendToServer(bio,protocol,strlen(protocol));
		int responseFromServer = readProResponseFromServer(bio, "OK", 2);
		free (protocol);
		return responseFromServer;
		
}
int requestSend(BIO *bio, unsigned char * request, unsigned char *filename){
	//1 is success
	long *fileLen = (long*) malloc (sizeof (long));
	unsigned char *fileInBytes = fileToByteArray(filename, fileLen);
	unsigned char fileLenArr[sizeof(long)];
	sprintf (fileLenArr,"%ld",*fileLen);
		
	if (sendProtocolExchangeWithServer(bio, request, filename, fileLenArr ) == 1){
		printf ("===========Sending file of size: %ld ================ \n", *fileLen)	;	
		sendFileToServer(bio,fileInBytes, *fileLen);
		//readProResponseFromServer(bio,"Done",4);
	}
	free (fileLen);
	free (fileInBytes);
	return 1;
}
/* Receives byte array from server and creates a file locally */

int requestReceive(BIO *bio, unsigned char *request, unsigned char *filename){
	unsigned char * protoResponse = 
						 receiveProtocolFromServer(bio,request,filename);
	int filesize = parseFilesize(protoResponse);

	unsigned char * fileInBytes = recvRequestFromServ(bio, filesize);
	
	
	
	createByteFile(filename,fileInBytes,filesize);
				
	free (protoResponse);
	free(fileInBytes);
	
	
	return -1;
		
}

/* Handles the request "send or "receive" for @param filename *
 * with the server. 
 * Sends server "filesize file \n" when using @param - request "send" to *
 * establish size of file to be sent                          */

int handleRequestToServer(BIO *bio, unsigned char *request, 
				  unsigned char *filename){
	//process request to server
	if (strcmp(request,"send") == 0){
		requestSend(bio,request,filename);
	}
	if (strcmp (request, "receive") == 0){
		printf("Sending receive command \n");
		requestReceive(bio,request,filename);
	}
	return 1;	
	

}


/* returns 1 if response is good
 * -1 if server failed to respond with ok */
 
int readProResponseFromServer (BIO *bio, unsigned char *expected, int protocolReplyLength){
	int bytesReceived = 0;
	unsigned char* recvBuf = (unsigned char*) malloc (protocolReplyLength+1);
	if ((bytesReceived = BIO_read(bio,recvBuf, protocolReplyLength)) <= 0){
		printf("Error reading protocol response from server\n");
	}
	
	recvBuf[bytesReceived] = '\0';
	
	
	if (strcmp(recvBuf, expected) == 0){
		free (recvBuf);
		return 1;
	}
	free (recvBuf);
	return -1;

}



int sendFileToServer (BIO* bio, unsigned char *request , int len){
		int bytesSent = 0;
		while ((bytesSent += 
				BIO_write(bio,request,len)) < len);
				
		printf ("Sent %d bytes of %d bytes\n", bytesSent,len);
		if (bytesSent <=0){
			printf ("Error sending \n");
		}
		return 1;


}

unsigned char *parseInputParam (char *param){
	if ((strcmp((const char*)param, "--send") == 0) || (strcmp((const char*)param,"--receive") == 0)){
		
		char *parsed = param;
		parsed +=2;
		
		return parsed;
	}
	else{
		char *garbage = strtok(param, "=");
		char *parsed = strtok(NULL," ");
		return parsed;
	}
	
}
		
int main (int count, char *args[]){
	SSL_CTX *ctx;
	char *hostname, *portnum;
	unsigned char *request, *filename;
	SSL_library_init();
	ctx = initCTX();
	if ( count != 5 ){
		printf("usage: %s --serverAddress=0.0.0 --port=1234  --send/receive ./file \n ", args[0]);
		exit(0);
	}
	
	//initialize SSL library
//	OpenSSL_add_all_algorithms();
	hostname = parseInputParam(args[1]);
	portnum = parseInputParam(args[2]);
	request = parseInputParam(args[3]);
	filename = args[4];	


	char *formattedServerPort = formatServerPort(hostname,portnum);

	BIO * serverConnection = connectSSL(ctx,formattedServerPort);
	
	int* messageLength = (int*) malloc (sizeof (int));
	srand(time(NULL));
	int number = rand() % 1000;
	
	unsigned char *challenge = (unsigned char*) malloc (4);
	sprintf(challenge,"%d",number);
	unsigned char* encryptedChallenge = encryptChallenge(challenge, messageLength);
	// Send Challenge to server
	sendToServer (serverConnection,encryptedChallenge, *messageLength );
	// Receive hash from server
	if (compareHashFromServer(serverConnection, challenge)){
		// handle request
		handleRequestToServer(serverConnection,
					request,filename); 

	}

	
	free(encryptedChallenge);
	free (messageLength);	
	free (challenge);	
	BIO_free_all(serverConnection);		
	free(formattedServerPort);
	SSL_CTX_free(ctx);
	EVP_cleanup();
	sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
	CRYPTO_cleanup_all_ex_data();
	return 0;
}
	
