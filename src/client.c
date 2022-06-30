#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <math.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <pthread.h>

int padding = RSA_PKCS1_PADDING;

int port_no;
char IP[16];
char private1[16];
char public2[16];

RSA *createRSA(unsigned char *key, int isPublic)
{
    RSA *rsa = NULL;
    BIO *keybio;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio == NULL)
    {
        printf("Failed to create BIO of key");
        return 0;
    }
    if (isPublic)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
    if (rsa == NULL)
    {
        printf("Failed to create RSA structure info");
    }

    return rsa;
}

int public_encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *encrypted)
{
    RSA *rsa = createRSA(key, 1);
    int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
    return result;
}

int private_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted)
{
    RSA *rsa = createRSA(key, 0);
    int result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}

void *recvmg(void *sock)
{
    char privateKey[8192];
    unsigned char dec[1024] = {};
    unsigned char enc[1024] = {};

    FILE *fp;

    int their_sock = *((int *)sock);
    //char msg[500];
    int len;
    int size;

    fp = fopen(private1, "r");
    if (fp == NULL)
    {
        printf("[CLIENT] First create a Private Key File\n");
        exit(0);
    }
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    fread(privateKey, size, 1, fp);
    fclose(fp);

    int encrypted_length;

    while ((len = recv(their_sock, enc, 1024, 0)) > 0)
    {

        printf("[CLIENT] Received Cipher Text : %s\n", enc);

        fp = fopen("encDataLen.txt", "r");
        fread(&encrypted_length, sizeof(encrypted_length), 1, fp);
        fclose(fp);

        int decrypted_length = private_decrypt(enc, encrypted_length, privateKey, dec);
        if (decrypted_length == -1)
        {
            printf("[CLIENT] Private Decrypt failed");
            exit(0);
        }

        printf("[CLIENT] Decrypted Plain Text : %s\n", dec);

        char ender[6];
        strcpy(ender, "exit\n");

        int flag = strcmp(dec, ender);
        if (flag == 0)
        {
            printf("[CLIENT] Client exiting.\n");
            exit(0);
        }

        memset(enc, '\0', sizeof(enc));
        memset(dec, '\0', sizeof(dec));
    }
}

int main(int argc, char *argv[])
{
    struct sockaddr_in their_addr;
    int my_sock;
    int their_sock;
    int their_addr_size;
    pthread_t sendt, recvt;
    char res[1024];
    char enc[1024];
    int len;

    FILE *fp;
    char publicKey[8192];
    int size;

    if (argc == 5)
    {
        printf("[CLIENT] IP Address : %s\n", argv[1]);
        printf("[CLIENT] Port No.: %s\n", argv[2]);
        printf("[CLIENT] This Client's Private Key File Name : %s\n", argv[3]);
        printf("[CLIENT] Other Client's Public Key File Name : %s\n", argv[4]);

        port_no = atoi(argv[2]);

        for (int i = 0; i < 16; i++)
        {
            IP[i] = argv[1][i];
        }

        for (int i = 0; i < 16; i++)
        {
            private1[i] = argv[3][i];
        }

        for (int i = 0; i < 16; i++)
        {
            public2[i] = argv[4][i];
        }
    }
    else if (argc > 5)
    {
        printf("[CLIENT] Argument Overflow.\n");
        return 1;
    }
    else
    {
        printf("[CLIENT] Enter IP Address: ");
        fgets(&IP, 16, stdin);

        printf("[CLIENT] Enter Port No.: ");
        scanf("%d", &port_no);

        printf("[CLIENT] Enter This Client's Private Key File Name: ");
        fgets(&private1, 16, stdin);

        printf("[CLIENT] Enter Other Client's Public Key File Name: ");
        fgets(&public2, 16, stdin);
    }

    printf("[CLIENT] Establishing connection with Server at Port Number %d and IP Address %s\n", port_no, IP);

    fp = fopen(public2, "r");
    if (fp == NULL)
    {
        printf("[CLIENT] This file does not exist in the current folder\n");
        exit(0);
    }
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    fread(publicKey, size, 1, fp);
    fclose(fp);

    //encrypted_length = public_encrypt(plainText, strlen(plainText), publicKey, encrypted);

    my_sock = socket(AF_INET, SOCK_STREAM, 0);
    memset(their_addr.sin_zero, '\0', sizeof(their_addr.sin_zero));
    their_addr.sin_family = AF_INET;
    their_addr.sin_port = htons(port_no);
    their_addr.sin_addr.s_addr = inet_addr(IP);

    if (connect(my_sock, (struct sockaddr *)&their_addr, sizeof(their_addr)) < 0)
    {
        perror("[CLIENT] Connection not established");
        exit(1);
    }

    inet_ntop(AF_INET, (struct sockaddr *)&their_addr, IP, INET_ADDRSTRLEN);
    printf("[CLIENT] Connected to Server at %s\n", IP);

    while (1)
    {
        pthread_create(&recvt, NULL, recvmg, &my_sock);
        while (fgets(res, 500, stdin) > 0)
        {
            int encrypted_length = public_encrypt(res, strlen(res), publicKey, enc);

            if (encrypted_length == -1)
            {
                printf("[CLIENT] Public Encrypt failed");
                close(my_sock);
                exit(0);
            }

            fp = fopen("encDataLen.txt", "w+");
            fwrite(&encrypted_length, sizeof(encrypted_length), 1, fp);
            fclose(fp);

            len = write(my_sock, enc, 1024);
            if (len < 0)
            {
                perror("[CLIENT] Message not sent");
                close(my_sock);
                exit(1);
            }

            char ender[6];
            strcpy(ender, "exit\n");

            int flag = strcmp(res, ender);
            if (flag == 0)
            {
                printf("[CLIENT] Client exiting.\n");
                exit(0);
            }

            memset(res, '\0', sizeof(res));
            memset(enc, '\0', sizeof(enc));
        }
        pthread_join(recvt, NULL);
    }

    close(my_sock);
}
