#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#define maxRequestSize 1024
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

	RSA_free(privateKey);
	return output;
	


}

unsigned char *fileToByteArray(const unsigned char* filename, long *fileLen){
		FILE *f1 = fopen (filename, "r");
		fseek(f1,0,SEEK_END);
		long len = ftell(f1);
		rewind(f1);
		
		//allocate mem for whole file
		unsigned char *ret = (unsigned char*) malloc (sizeof(char) * len);
		
		size_t result = fread(ret,1,len,f1);
		printf ("Filelength:%lu \n",len);
		*fileLen = len;
		printf ("FileLength Addr: %ld \n", *fileLen);
		if (result != len){
			printf ("Error reading from file\n");
		}
		
		
		fclose(f1);
		return ret;
}
void sendToClient(BIO* bio, unsigned char* message, int mLength ){
	if (BIO_write(bio,message, mLength) <= 0){
		printf( "Error sending to client \n");
		exit(1);
	}
}

unsigned char* recvRequestFromClient(BIO *bio, const int recvLen){
	unsigned char *recvBuf = (unsigned char*) malloc(recvLen +1);
	int bytesRecv = 0;
	printf ("Awaiting response from server \n");
	if ((bytesRecv =BIO_read(bio,recvBuf,recvLen)) <= 0 ){
		printf("Error reading data \n");
	}
	recvBuf[bytesRecv] = '\0';
	printf ("read data from server\n");

	return recvBuf;
}
unsigned char *getRequestFileandSize(const unsigned char * filename, long *filesize){
	
	unsigned char *fileInBytes = fileToByteArray(filename,filesize);
	printf ("File size of %ld \n", *filesize);
	return fileInBytes;
}
unsigned char *buildProtocolToClient (const unsigned char *filename, unsigned char *filesize){
	// place long into array to be cat into response
	
	unsigned char *protoResponse = (unsigned char *)
										malloc ( strlen(filename) + strlen(filesize) + 2 );
	memcpy(protoResponse,filesize, strlen(filesize));
	strcat(protoResponse, " " );
	strcat (protoResponse, filename);
	printf ("ProtoResponse: %s \n", protoResponse);
	return protoResponse;
}
int recvOKFromClient (BIO *bio){
	unsigned char *response  = recvRequestFromClient(bio,2);
	if ( strcmp ( response , "OK" ) == 0){
		free(response);
		return 1;
	}
	free(response);
	return -1;

	
}


int sendFileToClient (BIO* bio, unsigned char *request , int len){
		printf("Sending file \n");
		int bytesSent = 0;
		while ((bytesSent += 
				BIO_write(bio,request,len)) < len);
				
		printf ("Send %d bytes of %d bytes\n", bytesSent,len);
		if (bytesSent <=0){
			printf ("Error sending \n");
		}
		return 1;


}

int requestSend(BIO* bio, unsigned char * request, unsigned char* recvBuf){
		unsigned char * filesize = strtok (NULL, " " );
		unsigned char * filename = strtok (NULL, "");
		int fileSize = atoi((char *) filesize);
		printf ("Received:%s filesize:%d filename:%s \n" , request, fileSize, filename);
		sendToClient(bio,"OK",2);
		unsigned char * fileInBytes = recvRequestFromClient(bio,fileSize);
		printf ("Received file from client...\n");
		printf ("Filesize: %d \n",fileSize);
		createByteFile(filename,fileInBytes,fileSize);
		free(fileInBytes);

}

int requestRecv (BIO *bio, unsigned char *recvBuf){
	unsigned char * filename = strtok (NULL, "");
	long * filesize = (long*) malloc (sizeof(long));
	unsigned char *fileInBytes = getRequestFileandSize(filename,filesize);
	unsigned char fileSizeArr[sizeof(long)];
	sprintf(fileSizeArr,"%ld",*filesize);
	unsigned char *protoRecv = buildProtocolToClient(filename,fileSizeArr);
	sendToClient (bio,protoRecv,strlen(protoRecv));
		
	if (recvOKFromClient(bio) != 1 ){
		printf ("error receiving ok from client \n");
	}
		
	sendFileToClient(bio,fileInBytes,*filesize);
					
	free(filesize);
	free (fileInBytes);
	free (protoRecv);
		
}

int handleRequestFromClient (BIO *bio){
	/* ========Read protocol================
	* if first word == send
	* 	recvSendFromClient)()
	* else
	* 	send filesize filename 
	* 	First Recv: "Ok"
	* 	Second Second : "byte arrayOfFile"
	* ==================================== */
	
	unsigned char *recvBuf = recvRequestFromClient(bio, maxRequestSize);
	unsigned char* request = strtok(recvBuf," ");
	printf("Request: %s \n", request);
	
	if (strcmp(request, "send") == 0){
		requestSend(bio,request,recvBuf);

		
		
	}
	
	if (strcmp (request, "receive") == 0){
		requestRecv(bio,recvBuf);
	
	} 
	
	free(recvBuf);
	return 0;
	
	
}

int createByteFile (unsigned char *filename, unsigned char *fileInBytes, int filesize){
		FILE * file;
		printf("Filesize: %d \n", filesize);
		file = fopen("test","w"); //change to w after debug
		fwrite (fileInBytes ,1,filesize,file);
		fclose(file);
		return 1;
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


	handleRequestFromClient(connection);
	BIO_free_all(connection);
	free((unsigned char*)challenge);
	free(hashedChallenge);
	free(signedHash);
	free (signedHashLength);	
	cleanUpOpenSSL();		
	return 0;
}

