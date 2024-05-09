/***********************************************************************

   File          : cse543-proto.c

   Description   : This is the network interfaces for the network protocol connection.


***********************************************************************/

/* Include Files */
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <stdint.h>

/* OpenSSL Include Files */
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

/* Project Include Files */
#include "cse543-util.h"
#include "cse543-network.h"
#include "cse543-proto.h"
#include "cse543-ssl.h"

/* Functional Prototypes */

/**********************************************************************

    Function    : make_req_struct
    Description : build structure for request from input
    Inputs      : rptr - point to request struct - to be created
                  filename - filename
                  cmd - command string (small integer value)
                  type - - command type (small integer value)
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int make_req_struct( struct rm_cmd **rptr, char *filename, char *cmd, char *type )
{
	struct rm_cmd *r;
	int rsize;
	int len; 

	assert(rptr != 0);
	assert(filename != 0);
	len = strlen( filename );

	rsize = sizeof(struct rm_cmd) + len;
	*rptr = r = (struct rm_cmd *) malloc( rsize );
	memset( r, 0, rsize );
	
	r->len = len;
	memcpy( r->fname, filename, r->len );  
	r->cmd = atoi( cmd );
	r->type = atoi( type );

	return 0;
}


/**********************************************************************

    Function    : get_message
    Description : receive data from the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to read
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int get_message( int sock, ProtoMessageHdr *hdr, char *block )
{
	/* Read the message header */
	recv_data( sock, (char *)hdr, sizeof(ProtoMessageHdr), 
		   sizeof(ProtoMessageHdr) );
	hdr->length = ntohs(hdr->length);
	assert( hdr->length<MAX_BLOCK_SIZE );
	hdr->msgtype = ntohs( hdr->msgtype );
	if ( hdr->length > 0 )
		return( recv_data( sock, block, hdr->length, hdr->length ) );
	return( 0 );
}

/**********************************************************************

    Function    : wait_message
    Description : wait for specific message type from the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to read
                  my - the message to wait for
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int wait_message( int sock, ProtoMessageHdr *hdr, 
                 char *block, ProtoMessageType mt )
{
	/* Wait for init message */
	int ret = get_message( sock, hdr, block );
	if ( hdr->msgtype != mt )
	{
		/* Complain, explain, and exit */
		char msg[128];
		sprintf( msg, "Server unable to process message type [%d != %d]\n", 
			 hdr->msgtype, mt );
		errorMessage( msg );
		exit( -1 );
	}

	/* Return succesfully */
	return( ret );
}

/**********************************************************************

    Function    : send_message
    Description : send data over the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to send
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int send_message( int sock, ProtoMessageHdr *hdr, char *block )
{
     int real_len = 0;

     /* Convert to the network format */
     real_len = hdr->length;
     hdr->msgtype = htons( hdr->msgtype );
     hdr->length = htons( hdr->length );
     if ( block == NULL )
          return( send_data( sock, (char *)hdr, sizeof(hdr) ) );
     else 
          return( send_data(sock, (char *)hdr, sizeof(hdr)) ||
                  send_data(sock, block, real_len) );
}

/**********************************************************************

    Function    : encrypt_message
    Description : Get message encrypted (by encrypt) and put ciphertext 
                   and metadata for decryption into buffer
    Inputs      : plaintext - message
                : plaintext_len - size of message
                : key - symmetric key
                : buffer - place to put ciphertext and metadata for 
                   decryption on other end
                : len - length of the buffer after message is set 
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/
/*** YOUR CODE ***/
int encrypt_message( unsigned char *plaintext, unsigned int plaintext_len, unsigned char *key, 
		     unsigned char *buffer, unsigned int *len )
{
	/*
	* Given plaintext, its length plaintext_len and key
	* Encrypt it using the key and copy the resulting encrypted data into buffer
	*/


	/*
	* Encrypted Buffer :- a Tag + an IV + Cipher Text
	*/
	printf("plaintext: %s\n", plaintext);
	unsigned char *tag;
	unsigned char *ciphertext;
	// len = plaintext_len;

	unsigned int ivlen = 16;
	unsigned char *iv = (unsigned char*)malloc(ivlen);

	int random_IV = generate_pseudorandom_bytes(iv, ivlen);
	// assert( random_IV == 0);
	if(random_IV == -1){
		printf("Failed creating IV for encryption!\n");
		return -1;
	}

	printf("key: %s\n", &key);
	// printf("EM AVTUNDI RA!!!\n");
	ciphertext = (unsigned char *)malloc(plaintext_len);
	tag = (unsigned char *)malloc(TAGSIZE);
	int clen = encrypt(plaintext, plaintext_len, (unsigned char *)NULL, 0, &key, iv, ciphertext, tag);
	
	if(clen == -1 || clen > plaintext_len){
		printf("Failed encrypting message!\n");
		return -1;
	}
	// assert((clen > 0) && (clen <= plaintext_len));

	printf("Plaintext is:\n");
	BIO_dump_fp (stdout, (const char *)plaintext, plaintext_len);

	printf("Tag is: \n");
	BIO_dump_fp (stdout, (const char *)tag, TAGSIZE);

	// buffer = tag + IV + ciphertext

	//copying tag to buffer
	memcpy(buffer, tag, TAGSIZE);
	buffer += TAGSIZE;

	// printf("@@ ivlen, clen, %d, %d\n", )
	//copying ivlen to buffer
	// memcpy(buffer, &ivlen, sizeof(unsigned int));
	// buffer += sizeof(unsigned int);

	//copying clen to buffer
	// memcpy(buffer, &clen, sizeof(unsigned int));
	// buffer += sizeof(unsigned int);

	//copying iv to buffer
	memcpy(buffer, iv, ivlen);
	buffer += ivlen;

	//copying cipher to buffer
	memcpy(buffer, ciphertext, clen);
	buffer += clen;

	// buffer = buffer - clen - TAGSIZE - ivlen - 2*sizeof(unsigned int);
	// finally buffer = tag + ivlen + clen + IV + Ciphertext
	/*
	* Take inspiration from Test AES function - We are trying to employ Symmetric Key Cryptography here
	*/
	*len = TAGSIZE + ivlen + clen;
	// len = clen;
	printf("Done Encrypting message\n");
	return 0;

}



/**********************************************************************

    Function    : decrypt_message
    Description : Produce plaintext for given ciphertext buffer (ciphertext+tag) using key 
    Inputs      : buffer - encrypted message - includes tag
                : len - length of encrypted message and tag
                : key - symmetric key
                : plaintext - message
                : plaintext_len - size of message
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/
/*** YOUR CODE ***/
int decrypt_message( unsigned char *buffer, unsigned int len, unsigned char *key, 
		     unsigned char *plaintext, unsigned int *plaintext_len )
{
	/*
	* Given buffer, its length len and key
	* Decrypt it using the key and copy the resulting data into plaintext, its length into plaintext_len
	*/

	/*
	* Take inspiration from Test AES function - We are trying to employ Symmetric Key Cryptography here
	*/

	unsigned char *tag, *iv;
	unsigned int ivlen = 16, clen;
	unsigned char *ciphertext;


	clen = len - TAGSIZE - ivlen;

	printf("$$CLEN: %d\n", clen);
	tag = (unsigned char*)malloc(TAGSIZE);

	// ivlen = (len - TAGSIZE)/2;
	// clen = ivlen;

	// buffer = tag + IV + ciphertext

	// copying tag
	memcpy(tag, buffer, TAGSIZE);
	buffer += TAGSIZE;

	//copying
	//copying IV len and clen
	// memcpy(&ivlen, buffer, sizeof(unsigned int));
	// buffer += sizeof(unsigned int);

	// memcpy(&clen, buffer, sizeof(unsigned int));
	// buffer += sizeof(unsigned int);

	// printf("$$ ivlen, clen: %d, %d\n", ivlen, clen);

	iv = (unsigned char *)malloc(ivlen);
	ciphertext = (unsigned char *)malloc(clen);

	memcpy(iv, buffer, ivlen);
	buffer += ivlen;

	printf("Torture in decrypt\n");
	//copying ciphertext
	memcpy(ciphertext, buffer, clen);
	// buffer += clen;


	plaintext = (unsigned char *) malloc (clen + TAGSIZE);
	*plaintext_len = decrypt( ciphertext, clen, (unsigned char *) NULL, 0, tag, key, iv, plaintext );

	printf("decrypted_message: %s\n", plaintext);

	if(plaintext_len < 0){
		printf("Failed decryption!\n");
		return -1;
	}

	return 0;


}



/**********************************************************************

    Function    : extract_public_key
    Description : Create public key data structure from network message
    Inputs      : buffer - network message  buffer
                : size - size of buffer
                : pubkey - public key pointer
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int extract_public_key( char *buffer, unsigned int size, EVP_PKEY **pubkey )
{
	RSA *rsa_pubkey = NULL;
	FILE *fptr;

	*pubkey = EVP_PKEY_new();

	/* Extract server's public key */
	/* Make a function */
	fptr = fopen( PUBKEY_FILE, "w+" );

	if ( fptr == NULL ) {
		errorMessage("Failed to open file to write public key data");
		return -1;
	}

	fwrite( buffer, size, 1, fptr );
	rewind(fptr);

	/* open public key file */
	if (!PEM_read_RSAPublicKey( fptr, &rsa_pubkey, NULL, NULL))
	{
		errorMessage("Cliet: Error loading RSA Public Key File.\n");
		return -1;
	}

	if (!EVP_PKEY_assign_RSA(*pubkey, rsa_pubkey))
	{
		errorMessage("Client: EVP_PKEY_assign_RSA: failed.\n");
		return -1;
	}

	fclose( fptr );
	return 0;
}


/**********************************************************************

    Function    : generate_pseudorandom_bytes
    Description : Generate pseudirandom bytes using OpenSSL PRNG 
    Inputs      : buffer - buffer to fill
                  size - number of bytes to get
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int generate_pseudorandom_bytes( unsigned char *buffer, unsigned int size)
{	
	int rand_out = RAND_bytes(buffer, size);
	if(rand_out != 1){
		return -1;
	}
	
	return 0;
}


/**********************************************************************

    Function    : seal_symmetric_key
    Description : Encrypt symmetric key using public key
    Inputs      : key - symmetric key
                  keylen - symmetric key length in bytes
                  pubkey - public key
                  buffer - output buffer to store the encrypted seal key and ciphertext (iv?)
    Outputs     : len if successful, -1 if failure

***********************************************************************/
/*** YOUR CODE ***/
int seal_symmetric_key( unsigned char *key, unsigned int keylen, EVP_PKEY *pubkey, char *buffer )
{
	/*
	* Given symmetric key "key", its length keylen and a known public key "pubkey"
	* Encrypt the key using the RSA pubkey and copy the resulting encrypted data into buffer
	*/

	/*
	* The Encrypted Buffer needs the following - Encrypted RSA pubkey, its length, an IV, its length, Ciphertext of Symmetric Key, its length
	* One Such implementation is :- encypted rsa pubkey length + iv length + ciphertext length + encrypted rsa pubkey + IV + Ciphertext
	*/

	/*
	* Take inspiration from Test RSA function - We are trying to employ Asymmetric Key Cryptography here
	*/

	unsigned int len = 0;
	unsigned char *ciphertext;
	unsigned char *ek;
	unsigned int ekl;
	unsigned char *iv;
	unsigned int ivl;

	printf("*** Sealing The Symmetric Key! ***\n");
	// printf ("key = %s\n", key);
	printf ("pubkey = %s\n", pubkey);
	printf("keylen = %d\n", keylen);
	printf("buffer = %s\n", buffer);
	len = rsa_encrypt(key, keylen, &ciphertext, &ek, &ekl, &iv, &ivl, pubkey);
	// len = rsa_encrypt(key, keylen, &ciphertext, &ek, &ekl, &iv, &ivl, pubkey);
	printf("## ekl, ivl, clen = %d, %d, %d\n", ekl, ivl, len);
	// printf("ek = %s\n", ek);
	printf("done with rsa encryption\n");
	if(len < 0){
		printf("Key encryption failed!\n");
		return -1;
	}

	// printf("Encrypted Symmetric key is :\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, len);

	// adding encrypted key len to buffer
	memcpy(buffer, &ekl, sizeof(unsigned int));
	buffer = buffer + sizeof(unsigned int);
	// adding initializing vector len to buffer
	memcpy(buffer, &ivl, sizeof(unsigned int));
	buffer = buffer + sizeof(unsigned int);

	// adding clen to buffer
	memcpy(buffer, &len, sizeof(unsigned int));
	buffer = buffer + sizeof(unsigned int);

	// adding encrypted key to buffer
	memcpy(buffer, ek, ekl);
	buffer = buffer + ekl;

	// adding i vector to buffer
	memcpy(buffer, iv, ivl);
	buffer = buffer + ivl;

	// adding the final cipher text to buffer
	memcpy(buffer, ciphertext, len);

	// buffer = buffer - 3*(sizeof(unsigned int)) - ekl - ivl - len;
	// printf("Buffer content: %s\n", *buffer);
    // Finally buffer = ekl + ivl + clen + ek + iv + ctext
	
	printf("DONE SEALING SYMMETRIC KEY\n");

	// return len;
	return 3*(sizeof(unsigned int)) + ekl + ivl + len;
}

/**********************************************************************

    Function    : unseal_symmetric_key
    Description : Perform SSL unseal (open) operation to obtain the symmetric key
    Inputs      : buffer - buffer of crypto data for decryption (ek, iv, ciphertext)
                  len - length of buffer
                  pubkey - public key 
                  key - symmetric key (plaintext from unseal)
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/
/*** YOUR CODE ***/
int unseal_symmetric_key( char *buffer, unsigned int len, EVP_PKEY *privkey, unsigned char **key )
{
	/*
	* Given buffer, its length len and a known private key "privkey"
	* Decrypt it using the private key and copy the resulting data into key
	*/

	/*
	* Remember : The buffer could be something like this ("encypted rsa pubkey length + iv length + ciphertext length + encrypted rsa pubkey + IV + Ciphertext")
	*/

	/*
	* Take inspiration from Test RSA function - We are trying to employ Asymmetric Key Cryptography here
	*/
	printf("*** Unsealing Symmetric Key! ***\n");
	unsigned char *ek, *iv, *ciphertext, *plaintext;
	unsigned int ekl, ivl, cipher_len;

	printf("buffer = %s\n", buffer);
    // Finally buffer = ekl + ivl + clen + ek + iv + ctext

	// copy encrypting key len to ekl
	memcpy(&ekl, buffer, sizeof(unsigned int));
	buffer = buffer + sizeof(unsigned int);

	// copy ivlen to ivl
	memcpy(&ivl, buffer, sizeof(unsigned int));
	buffer = buffer + sizeof(unsigned int);

	memcpy(&cipher_len, buffer, sizeof(unsigned int));
	buffer = buffer + sizeof(unsigned int);

	printf("ekl, ivl, clen = %d, %d, %d\n", ekl, ivl, cipher_len);
	// creating ekl and iv buffers

	ek = (unsigned char*) malloc(ekl);
	iv = (unsigned char*) malloc(ivl);
	ciphertext = (unsigned char*) malloc(cipher_len);

	if (ek == NULL){
		printf("Encrypted Key not found!\n");
		return -1;
	}

	if (iv == NULL){
		printf("Initialization Vector not found!\n");
		return -1;
	}

	//copy encrypted key
	memcpy(ek, buffer, ekl);
	buffer = buffer + ekl;

	//copy init vec
	memcpy(iv, buffer, ivl);
	buffer = buffer + ivl;

	memcpy(ciphertext, buffer, cipher_len);
	// assign remaining as cipher
	// ciphertext = (unsigned char*) buffer;

	// cipher_len = len - (buffer - ciphertext); //?

	int rsa_len = rsa_decrypt(ciphertext, cipher_len, ek, ekl, iv, ivl, &plaintext, privkey);

	printf("DONE UNSEALING SYMMETRIC KEY\n");
	printf("Unsealed key: %s\n", plaintext);

	return 0;
}


/* 

  CLIENT FUNCTIONS 

*/



/**********************************************************************

    Function    : client_authenticate
    Description : this is the client side of the exchange
    Inputs      : sock - server socket
                  session_key - the key resulting from the exchange
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/
/*** YOUR CODE ***/
int client_authenticate( int sock, unsigned char **session_key )
{
	/*
	* Send Message to server with header CLIENT_INIT_EXCHANGE
	*/
	printf("Beginning client authentication....\n");
	unsigned char *buffer = malloc(MAX_BLOCK_SIZE);

	ProtoMessageHdr initExchange;
	initExchange.msgtype = CLIENT_INIT_EXCHANGE;
	initExchange.length = 0;
	printf("sent init exchange\n", initExchange.msgtype);
	send_message(sock, &initExchange, NULL);

	/*
	* Wait for Message from server with header SERVER_INIT_RESPONSE
	* Extract Pub Key out of the message -> Create a new Symmetric Key -> Encrypt it using the Pub Key of server
	*/
	ProtoMessageHdr initResponse;

	unsigned char *pubkeyc = malloc(MAX_BLOCK_SIZE);
	wait_message(sock, &initResponse, pubkeyc, SERVER_INIT_RESPONSE);

	// printf("initResponse len = %d\n", initResponse.length);
	// printf("pubkeyc %s\n", pubkeyc);
	//extracting public key

	// Print buffer content and symmetric key
    printf("Buffer content after SERVER_INIT_RESPONSE: ");
    printBuffer(pubkeyc, initResponse.length);
    printf("Symmetric Key after SERVER_INIT_RESPONSE: %s\n", symmetric_key);


	EVP_PKEY *pub_key;
	int ext_out = extract_public_key(pubkeyc, initResponse.length, &pub_key);
	
	// memcpy(&pubkeyc, buffer, MAX_BLOCK_SIZE);
	// buffer -= MAX_BLOCK_SIZE;
	printf("%d, Extract public key: %s, size: %d\n", ext_out, pub_key, EVP_PKEY_size(pub_key));
	// create symmetric key 
	// printf("Received pubkey: %s\n", pub_key);
	unsigned char *symmetric_key;
	symmetric_key = (unsigned char*)malloc(KEYSIZE);
	int sym_out = generate_pseudorandom_bytes(symmetric_key, KEYSIZE);

	printf("Symmetric Key after generating: %s\n", symmetric_key);

	// printf("created symmetric key: %s\n", symmetric_key);
	int len = seal_symmetric_key(symmetric_key, KEYSIZE, pub_key, buffer);

	/*
	* Send message to server with header CLIENT_INIT_ACK
	* The encrypted symmetric key from previous phase should be sent here
	*/

	printf("CLIENT KEY: %s\n", symmetric_key);
	ProtoMessageHdr initAck;
	initAck.msgtype = CLIENT_INIT_ACK;
	initAck.length = len;
	// printBuffer("Sym Key Buffer",buffer, len);
	send_message(sock, &initAck, buffer);
	printf("Sent Symmetric Key in buffer\n");
	/*
	* Wait message from server with header SERVER_INIT_ACK
	* Decrypt the message using the symmetric key and make sure the code doesn't break. 
	* This would mean both Client and Server have the same symmetric key now and the SSH connection is successful
	*/
	ProtoMessageHdr serverInitAck;
	unsigned char *message = malloc(MAX_BLOCK_SIZE);
	wait_message(sock, &serverInitAck, message, SERVER_INIT_ACK);
	printf("Received message from server!\n");
	int msg_len = serverInitAck.length;
	

	// Print buffer content and symmetric key
    printf("Buffer content after SERVER_INIT_ACK: ");
    printBuffer(message, msg_len);
    printf("Symmetric Key after SERVER_INIT_ACK: %s\n", symmetric_key);

	//message decrypt using symmetric key
	// int unseal_out = unseal_symmetric_key(buffer, msg_len, pub_key, symmetric_key);

	printf("Chee neeyamma em torture ra %d\n", msg_len);
	
	unsigned char *plain_message = malloc(MAX_BLOCK_SIZE);
	unsigned int plain_message_len;

	decrypt_message(message, msg_len, symmetric_key, plain_message, &plain_message_len);

	printf("Message: %s\n", plain_message);

	/*
		plaintext = (unsigned char *)malloc( clen+TAGSIZE );
		memset( plaintext, 0, clen+TAGSIZE ); 
		plen = decrypt( ciphertext, clen, (unsigned char *) NULL, 0, 
				tag, key, iv, plaintext );
		assert( plen > 0 );
	
	*/
	/*
	* Store the Symmetric key in session_key for later use. 
	*/
	// memcpy(session_key, symmetric_key, KEYSIZE);
	*session_key = symmetric_key;
	return 0;
}

/**********************************************************************

    Function    : transfer_file
    Description : transfer the entire file over the wire
    Inputs      : r - rm_cmd describing what to transfer and do
                  fname - the name of the file
                  sz - this is the size of the file to be read
                  key - the cipher to encrypt the data with
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int transfer_file( struct rm_cmd *r, char *fname, int sock, 
		   unsigned char *key )
{
	/* Local variables */
	int readBytes = 1, totalBytes = 0, fh;
	unsigned int outbytes;
	ProtoMessageHdr hdr;
	char block[MAX_BLOCK_SIZE];
	char outblock[MAX_BLOCK_SIZE];

	/* Read the next block */
	printf ("\n\nfile name: %s\n\n", fname);
	if ( (fh=open(fname, O_RDONLY, 0)) == -1 )
	{
		/* Complain, explain, and exit */
		char msg[128];
		sprintf( msg, "failure opening file [%.64s]\n", fname );
		errorMessage( msg );
		exit( -1 );
	}

	/* Send the command */
	hdr.msgtype = FILE_XFER_INIT;
	hdr.length = sizeof(struct rm_cmd) + r->len;
	send_message( sock, &hdr, (char *)r );

	/* Start transferring data */
	while ( (r->cmd == CMD_CREATE) && (readBytes != 0) )
	{
		/* Read the next block */
		if ( (readBytes=read( fh, block, BLOCKSIZE )) == -1 )
		{
			/* Complain, explain, and exit */
			errorMessage( "failed read on data file.\n" );
			exit( -1 );
		}
		
		/* A little bookkeeping */
		totalBytes += readBytes;
		printf( "Reading %10d bytes ...\r", totalBytes );

		/* Send data if needed */
		if ( readBytes > 0 ) 
		{
#if 1
			printf("Block is:\n");
			BIO_dump_fp (stdout, (const char *)block, readBytes);
#endif

			/* Encrypt and send */
			encrypt_message( (unsigned char *)block, readBytes, key, 
					 (unsigned char *)outblock, &outbytes );
			hdr.msgtype = FILE_XFER_BLOCK;
			hdr.length = outbytes;
			send_message( sock, &hdr, outblock );
		}
	}

	/* Send the ack, wait for server ack */
	hdr.msgtype = EXIT;
	hdr.length = 0;
	send_message( sock, &hdr, NULL );
	wait_message( sock, &hdr, block, EXIT );

	/* Clean up the file, return successfully */
	close( fh );
	return( 0 );
}


/**********************************************************************

    Function    : client_secure_transfer
    Description : this is the main function to execute the protocol
    Inputs      : r - cmd describing what to transfer and do
                  fname - filename of the file to transfer
                  address - address of the server
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int client_secure_transfer( struct rm_cmd *r, char *fname, char *address ) 
{
	/* Local variables */
	unsigned char *key;
	int sock;

	sock = connect_client( address );
	// crypto setup, authentication
	client_authenticate( sock, &key );
	// symmetric key crypto for file transfer
	transfer_file( r, fname, sock, key );
	// Done
	close( sock );

	/* Return successfully */
	return( 0 );
}

/* 

  SERVER FUNCTIONS 

*/

/**********************************************************************

    Function    : test_rsa
    Description : test the rsa encrypt and decrypt
    Inputs      : 
    Outputs     : 0

***********************************************************************/

int test_rsa( EVP_PKEY *privkey, EVP_PKEY *pubkey )
{
	unsigned int len = 0;
	unsigned char *ciphertext;
	unsigned char *plaintext;
	unsigned char *ek;
	unsigned int ekl; 
	unsigned char *iv;
	unsigned int ivl;

	printf("*** Test RSA encrypt and decrypt. ***\n");

	len = rsa_encrypt( (unsigned char *)"help me, mr. wizard!", 20, &ciphertext, &ek, &ekl, &iv, &ivl, pubkey );

#if 1
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, len);
#endif

	len = rsa_decrypt( ciphertext, len, ek, ekl, iv, ivl, &plaintext, privkey );

	printf("Msg: %s\n", plaintext );
    
	return 0;
}


/**********************************************************************

    Function    : test_aes
    Description : test the aes encrypt and decrypt
    Inputs      : 
    Outputs     : 0

***********************************************************************/

int test_aes( )
{
	int rc = 0;
	unsigned char *key;
	unsigned char *ciphertext, *tag;
	unsigned char *plaintext;
	unsigned char *iv = (unsigned char *)"0123456789012345";
	int clen = 0, plen = 0;
	unsigned char msg[] = "Help me, Mr. Wizard!";
	unsigned int len = strlen((char *)msg);

	printf("*** Test AES encrypt and decrypt. ***\n");

	/* make key */
	key= (unsigned char *)malloc( KEYSIZE );
	rc = generate_pseudorandom_bytes( key, KEYSIZE );	
	assert( rc == 0 );

	/* perform encrypt */
	ciphertext = (unsigned char *)malloc( len );
	tag = (unsigned char *)malloc( TAGSIZE );
	clen = encrypt( msg, len, (unsigned char *)NULL, 0, key, iv, ciphertext, tag);
	assert(( clen > 0 ) && ( clen <= len ));

#if 1
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, clen);
	
	printf("Tag is:\n");
	BIO_dump_fp (stdout, (const char *)tag, TAGSIZE);
#endif

	/* perform decrypt */
	plaintext = (unsigned char *)malloc( clen+TAGSIZE );
	memset( plaintext, 0, clen+TAGSIZE ); 
	plen = decrypt( ciphertext, clen, (unsigned char *) NULL, 0, 
		       tag, key, iv, plaintext );
	assert( plen > 0 );

	/* Show the decrypted text */
#if 0
	printf("Decrypted text is: \n");
	BIO_dump_fp (stdout, (const char *)plaintext, (int)plen);
#endif
	
	printf("Msg: %s\n", plaintext );
    
	return 0;
}


/**********************************************************************

    Function    : server_protocol
    Description : server processing of crypto protocol
    Inputs      : sock - server socket
                  key - the key resulting from the protocol
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/
/*** YOUR_CODE ***/
int server_protocol( int sock, char *pubfile, EVP_PKEY *privkey, unsigned char **enckey )
{
/*
	* Couterparts of client actions that the server needs to take.
	*/
	/*
	* Wait for Message to server with header CLIENT_INIT_EXCHANGE
	*/
	printf("wait for init exchange\n");
	ProtoMessageHdr initExchange;
	wait_message(sock,&initExchange,NULL,CLIENT_INIT_EXCHANGE);
	/*
	* Send Message from server with header SERVER_INIT_RESPONSE
	*/
	printf("Received message from client!\n");
	ProtoMessageHdr initResponse;
	initResponse.msgtype=SERVER_INIT_RESPONSE;
	unsigned char* pubkeyc = malloc(MAX_BLOCK_SIZE);
	initResponse.length=buffer_from_file(pubfile,&pubkeyc);
	/* Extract server's public key */
	/* Make a function */
	printf("send init response with pub key\n");
	send_message(sock,&initResponse,(char *)pubkeyc);
	/*
	* Wait for message to server with header CLIENT_INIT_ACK
	*/

	fflush(stdout);
	ProtoMessageHdr initAck;
	char* symKeyBuffer=malloc(MAX_BLOCK_SIZE);
	unsigned char* symKey;
	printf("wait for sealed symmetric key\n");
	wait_message(sock,&initAck,symKeyBuffer,CLIENT_INIT_ACK);
	if (symKeyBuffer == NULL){
		errorMessage("init ack recieve error");
		return -1;
	}
	printBuffer("Sym Key Buffer",symKeyBuffer, initAck.length);
	fflush(stdout);
	printf("unseal symmetric key\n");
	unseal_symmetric_key(symKeyBuffer,initAck.length, privkey, &symKey);
	
	printf("Server sym: %s\n", symKey);
	/*
	* Send message from server with header SERVER_INIT_ACK
	*/
	initAck.msgtype=SERVER_INIT_ACK;
	unsigned char* buffer=malloc(MAX_BLOCK_SIZE);
	unsigned int len;
	unsigned char message[] = "Complete";
	int messageLen = strlen((char *)message);
	printf("encrypt \"complete\"\n");
	encrypt_message(message, messageLen,symKey,buffer,&len);
	if (messageLen < 1){
		errorMessage("init ack encryption error");
		return -1;
	}
	initAck.length= len;
	// printf("message in buffer: %s\n", buffer);
	char* bufferc = (char*) buffer;
	printf("send encrypted \"complete\"\n");
	send_message(sock, &initAck, bufferc);
	/*
	* Store the Symmetric key in session_key for later use. 
	*/
	printf("store sym key\n");
	*enckey = symKey;
	return 0;
}


/**********************************************************************

    Function    : receive_file
    Description : receive a file over the wire
    Inputs      : sock - the socket to receive the file over
                  key - the cicpher used to encrypt the traffic
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

#define FILE_PREFIX "./shared/"

int receive_file( int sock, unsigned char *key ) 
{
	/* Local variables */
	unsigned long totalBytes = 0;
	int done = 0, fh = 0;
	unsigned int outbytes;
	ProtoMessageHdr hdr;
	struct rm_cmd *r = NULL;
	char block[MAX_BLOCK_SIZE];
	unsigned char plaintext[MAX_BLOCK_SIZE];
	char *fname = NULL;
	int rc = 0;

	/* clear */
	bzero(block, MAX_BLOCK_SIZE);

	/* Receive the init message */
	wait_message( sock, &hdr, block, FILE_XFER_INIT );

	/* set command structure */
	struct rm_cmd *tmp = (struct rm_cmd *)block;
	unsigned int len = tmp->len;
	r = (struct rm_cmd *)malloc( sizeof(struct rm_cmd) + len );
	r->cmd = tmp->cmd, r->type = tmp->type, r->len = len;
	memcpy( r->fname, tmp->fname, len );

	/* open file */
	if ( r->type == TYP_DATA_SHARED ) {
		unsigned int size = r->len + strlen(FILE_PREFIX) + 1;
		char *fname = (char *)malloc( size );
		snprintf( fname, size, "%s%.*s", FILE_PREFIX, (int) r->len, r->fname );
		if ( (fh=open( fname, O_WRONLY|O_CREAT|O_TRUNC, 0700)) > 0 );  // TJ: need to change this for students
		else assert( 0 );
	}
	else assert( 0 );

	/* read the file data, if it's a create */ 
	if ( r->cmd == CMD_CREATE ) {
		/* Repeat until the file is transferred */
		printf( "Receiving file [%s] ..\n", fname );
		while (!done)
		{
			/* Wait message, then check length */
			get_message( sock, &hdr, block );
			if ( hdr.msgtype == EXIT ) {
				done = 1;
				break;
			}
			else
			{
				/* Write the data file information */
				rc = decrypt_message( (unsigned char *)block, hdr.length, key, 
						      plaintext, &outbytes );
				assert( rc  == 0 );
				write( fh, plaintext, outbytes );

#if 1
				printf("Decrypted Block is:\n");
				BIO_dump_fp (stdout, (const char *)plaintext, outbytes);
#endif

				totalBytes += outbytes;
				printf( "Received/written %ld bytes ...\n", totalBytes );
			}
		}
		printf( "Total bytes [%ld].\n", totalBytes );
		/* Clean up the file, return successfully */
		close( fh );
	}
	else {
		printf( "Server: illegal command %d\n", r->cmd );
		//	     exit( -1 );
	}

	/* Server ack */
	hdr.msgtype = EXIT;
	hdr.length = 0;
	send_message( sock, &hdr, NULL );

	return( 0 );
}

/**********************************************************************

    Function    : server_secure_transfer
    Description : this is the main function to execute the protocol
    Inputs      : pubkey - public key of the server
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int server_secure_transfer( char *privfile, char *pubfile )
{
	/* Local variables */
	int server, errored, newsock;
	RSA *rsa_privkey = NULL, *rsa_pubkey = NULL;
	RSA *pRSA = NULL;
	EVP_PKEY *privkey = EVP_PKEY_new(), *pubkey = EVP_PKEY_new();
	fd_set readfds;
	unsigned char *key;
	FILE *fptr;

	/* initialize */
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	ERR_load_crypto_strings();

	/* Connect the server/setup */
	server = server_connect();
	errored = 0;

	/* open private key file */
	fptr = fopen( privfile, "r" );
	assert( fptr != NULL);
	if (!(pRSA = PEM_read_RSAPrivateKey( fptr, &rsa_privkey, NULL, NULL)))
	{
		fprintf(stderr, "Error loading RSA Private Key File.\n");

		return 2;
	}

	if (!EVP_PKEY_assign_RSA(privkey, rsa_privkey))
	{
		fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
		return 3;
	}
	fclose( fptr ); 

	/* open public key file */
	fptr = fopen( pubfile, "r" );
	assert( fptr != NULL);
	if (!PEM_read_RSAPublicKey( fptr , &rsa_pubkey, NULL, NULL))
	{
		fprintf(stderr, "Error loading RSA Public Key File.\n");
		return 2;
	}

	if (!EVP_PKEY_assign_RSA( pubkey, rsa_pubkey))
	{
		fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
		return 3;
	}
	fclose( fptr );

	// Test the RSA encryption and symmetric key encryption
	test_rsa( privkey, pubkey );
	test_aes();

	/* Repeat until the socket is closed */
	while ( !errored )
	{
		FD_ZERO( &readfds );
		FD_SET( server, &readfds );
		if ( select(server+1, &readfds, NULL, NULL, NULL) < 1 )
		{
			/* Complain, explain, and exit */
			char msg[128];
			sprintf( msg, "failure selecting server connection [%.64s]\n",
				 strerror(errno) );
			errorMessage( msg );
			errored = 1;
		}
		else
		{
			/* Accept the connect, receive the file, and return */
			if ( (newsock = server_accept(server)) != -1 )
			{
				/* Do the protocol, receive file, shutdown */
				server_protocol( newsock, pubfile, privkey, &key );
				receive_file( newsock, key );
				close( newsock );
			}
			else
			{
				/* Complain, explain, and exit */
				char msg[128];
				sprintf( msg, "failure accepting connection [%.64s]\n", 
					 strerror(errno) );
				errorMessage( msg );
				errored = 1;
			}
		}
	}

	/* Return successfully */
	return( 0 );
}

