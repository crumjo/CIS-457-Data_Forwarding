#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <pthread.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <string.h>

void handleErrors(void);
int rsa_encrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out);
int rsa_decrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);


struct thread_args
{
	int socket;
};

int kicked = 0;

void* worker(void* args)
{
	struct thread_args targs;
	memcpy(&targs, args, sizeof(struct thread_args));
	char receive[5000];

	while(strcmp(receive, "/quit\n") != 0 && strcmp(receive, "kicked\n") != 0)
	{
		recv(targs.socket, receive, 5000, 0);
		if (strcmp(receive, "kicked\n") == 0) 
		{
			printf("You were kicked\n");
			kicked = 1;
			exit(0);
		}
		printf("%s", receive);
	}

	return 0;
}

int main(int argc, char** argv)
{
	int sockfd = socket(AF_INET,SOCK_STREAM,0);
	
	if(sockfd<0)
	{
		printf("There was an error creating the socket\n");
		return 1;
	}
	int port;
	char* address = (char*) malloc(sizeof(char)*50);

	printf("Welcome to a simple chat client\n\n");
	printf("Please enter a port: ");

	scanf("%d", &port);

	printf("Please enter an address: ");

	scanf("%s", address);

	struct sockaddr_in serveraddr;
	serveraddr.sin_family=AF_INET;
	serveraddr.sin_port=htons(port);
	serveraddr.sin_addr.s_addr=inet_addr(address);
	socklen_t len = sizeof(serveraddr);

	int serversocket = connect(sockfd,(struct sockaddr*)&serveraddr,len);
	if(serversocket<0)
	{
		printf("There was an error connecting\n");
		return 1;
	}

	

	char temp[10];
	fgets(temp, 10, stdin);

	char send[5000];
	char username [100];
	int uniqname = 1;

	do
	{
		printf("Enter a username: ");
		fgets(username, 100, stdin);
		sendto(sockfd, username, 100, 0, (struct sockaddr*)&serveraddr, sizeof(serveraddr));

	}while (recv(sockfd, &uniqname, sizeof(int), 0) == 0);

	struct thread_args *args = malloc(sizeof(struct thread_args));
	memcpy(&args->socket, &sockfd, sizeof(int));

	pthread_t tid;
	pthread_create(&tid, NULL, worker, args);
	pthread_detach(tid);
	
	while (strcmp(send, "/quit\n") != 0 && kicked == 0)
	{
		printf("\nEnter a string: ");
		fgets(send, 5000, stdin);
		sendto(sockfd, send, 5000, 0, (struct sockaddr*)&serveraddr, sizeof(serveraddr));
		
		//
	}
	
	close(sockfd);
	return 0;
}


void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int rsa_encrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){ 
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  ctx = EVP_PKEY_CTX_new(key, NULL);
  if (!ctx)
    handleErrors();
  if (EVP_PKEY_encrypt_init(ctx) <= 0)
    handleErrors();
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0)
    handleErrors();
  return outlen;
}

int rsa_decrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){ 
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  ctx = EVP_PKEY_CTX_new(key,NULL);
  if (!ctx)
    handleErrors();
  if (EVP_PKEY_decrypt_init(ctx) <= 0)
    handleErrors();
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    handleErrors();
  if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    handleErrors();
  if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0)
    handleErrors();
  return outlen;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	    unsigned char *iv, unsigned char *plaintext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}