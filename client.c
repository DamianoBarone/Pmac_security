#include<stdlib.h>
#include<string.h>
#include<stdio.h>
#include<unistd.h>
#include<sys/socket.h>
#include<sys/select.h>
#include<sys/time.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<errno.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <omp.h>

#define NUMERO_TH_TEST 4
#define fixKey "12345678901234567890123456789012"

struct sockaddr_in srv_addr, my_addr, client_addr;
int sk,sudp;  			// socket: uno per server e uno per clientp2p
struct timeval  tempo;
char simbolo;
char shell;
char turno;
fd_set 	master,	//i descittori
read_fd; // fd di appoggio per la select
int		maxfd;

int conta;
void help()
{
    printf("ti verranno asseganti job da elaborare \n se vuoi uscire basta che scrivi !quit\n");
    
}


void print_bytes(const unsigned char* buf, int len) {
    int i;
    for (i = 0; i < len - 1; i++)

        printf("%02X", buf[len - 1]);
}
void quit()
{
    
  
    if (close(sk)==-1) //chiudo tcp
    {
        printf("errore chiusura");
        exit(1);
    }

    printf("ti sei disconesso con successo\n");
    exit(0);
}





void connectserver(char* ip, char* porta)
{
    long ret;
    sk = socket(AF_INET, SOCK_STREAM, 0);		//afinet =ipv4  stream e' TCP, 0 protoccolo
    if (sk==-1)
    {
        printf("errore nel creare socket\n");
        exit(1);
    }
    
    memset(&srv_addr, 0, sizeof(srv_addr));     //azzero la struttura
    srv_addr.sin_family=AF_INET;					// famiglia ipv4
    srv_addr.sin_port = htons(atoi(porta));			//porta
    ret = inet_pton(AF_INET, ip, &srv_addr.sin_addr); // per formato di rete
    
    if (ret==-1)
    {
        printf("errore formato di rete\n");
        exit(1);
    }
    
    
    ret = connect(sk,(struct sockaddr *)&srv_addr, sizeof(srv_addr));  // mi collego con il server
    
    if (ret==-1)
    {
        printf("errore connessione\n");
        exit(1);
    }
    else
        printf("connessione riuscita\n");
    return;
}



void calcolaLI(long i,unsigned char* l, unsigned char** p, int index)
{
    // i e' il numero di blocchi
    // n e' dimblocchi
    int n=16;
    char ris = 0;
    unsigned char L[16];
    //p=malloc(sizeof(unsigned char*)* i);
    p[0]=malloc(16);
#pragma omp parallel for num_threads ( NUMERO_TH_TEST )
    for (int z=0; z<n; z++) //prima volta
    {
        L[z]=l[z];
        p[0][z]=l[z];
    }
    
    
    char carry=0;
//ultimo char e ' per vedere se completato... ***********

    for (int z=1; z<index; z++) {           //scarto le prime L fino a index mio
        for (int j=0; j<16; j++) {
            ris = l[j]&127 || L[j]&127;
            //p[z][j]+= l[j] + carry;
            L[j]+=l[j] + carry;
            if (ris==1 && (L[j]&127)==0)
                carry=1;
            else
                carry=0;
            }
        carry=0;
        }
    if(index!=0)
    {
        for (int j=0; j<16; j++) //prima volta
        {
            ris = l[j]&127 || L[j]&127;
            p[0][j]= l[j] + carry + L[j];
            if (ris==1 && (p[0][j]&127)==0)
                carry=1;
            else
                carry=0;

        }
    }
    carry=0;

        for (int z=1; z<i; z++) { //L che mi servono dal mio index alla dim del blocco
            for (int j=0; j<16; j++) {
                ris = l[j]&127 || p[z-1][j]&127;
                p[z][j]= l[j] + carry + p[z-1][j];
                if (ris==1 && (p[z][j]&127)==0)
                    carry=1;
                else
                    carry=0;
                
            }
            carry=0;
        }
    
    
}

void mexserver() //gestisco i job
{
    
    long ret,quanti=0;
    unsigned char * msg;
    long numblocchi;
    unsigned char **p;
    unsigned char *zero;
    int index;
    EVP_CIPHER_CTX* ctx;
    unsigned char ** ciphertext;
  
    unsigned char* L;
    int outlen=0, outlen2=0;
    char *key=malloc(52), *recv_sha;
    char *recv_key=malloc(64);
    //key=malloc(32);
    ret = recv(sk, (void *)recv_key, 64, MSG_WAITALL);//key
    if(ret==-1) {
        printf("mexserver errore: errore in ricezione idjob dal server!\n");
        exit(1);
    }
    if (ret!=64 || ret==0)
    {
        printf("errore recv hash %d",ret);
    }
    
    // decifra key+hash
    EVP_CIPHER_CTX* ctx_key = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx_key);
	EVP_DecryptInit(ctx_key, EVP_aes_256_cbc(), fixKey, NULL);
	EVP_DecryptUpdate(ctx_key, key, &outlen, recv_key, 64);
	EVP_DecryptFinal(ctx_key, key+outlen, &outlen2);
	EVP_CIPHER_CTX_cleanup(ctx_key);
	EVP_CIPHER_CTX_free(ctx_key);
	recv_sha=key+32;
    zero=malloc(16);
    if(ret==0) { //server si e' disconnesso
        printf("Il server ha chiuso la connessione!!/n");
        exit(3);
    }
    ret = recv(sk, (void *)&index, sizeof(int), MSG_WAITALL); //mi serve per il calcolo di p
    if(ret==-1) {
        printf("mexserver errore: errore in ricezione lunghezza dal server3!\n");
        exit(1);
    }
    if (ret==0 && ret!=sizeof(int)) {
        printf("ERRORE RECV INDEX%ld",ret);
    }
        ret = recv(sk, (void *)&quanti, sizeof(long), MSG_WAITALL); //ricevo lunghezza stringa
        if(ret==-1) {
            printf("mexserver errore: errore in ricezione lunghezza dal server1!\n");
            exit(1);
        }
    if(ret==0) {
        printf(" ls recv di quanti vale zero\n");
        exit(1);
    }
    if ( ret!=sizeof(long)) {
        printf("ERRORE RECV  QUANTI");
    }
    msg=malloc(quanti);
  ret = recv(sk, (void *)msg, quanti, MSG_WAITALL); //ricevo file da cifrare
    if(ret==-1) {
        printf("mexserver errore: errore in ricezione lunghezza dal server2!\n");
        exit(1);
    }
    if ( ret!=quanti) {
        printf("ERRORE RECV  messaggio%ld\n",ret);
    }
    
    // calcolo hash
    char *sha1=malloc(20);
    SHA_CTX *sha_ctx=(SHA_CTX *)malloc(sizeof(SHA_CTX));
	if (!SHA1_Init(sha_ctx)) {
		perror("sha init error\n");
		exit(-1);
	}
	if (!SHA1_Update(sha_ctx, (unsigned char*)key, 32)) {
		perror("sha update error\n");
		exit(-1);
	}
	if (!SHA1_Update(sha_ctx, (unsigned char*)&index, sizeof(int))) {
		perror("sha update error\n");
		exit(-1);
	}
	if (!SHA1_Update(sha_ctx, (unsigned char*)&quanti, sizeof(long))) {
		perror("sha update error\n");
		exit(-1);
	}
	if (!SHA1_Update(sha_ctx, (unsigned char*)msg, quanti)) {
		perror("sha update error\n");
		exit(-1);
	}
	if (!SHA1_Final(sha1, sha_ctx)) {
		perror("sha final error\n");
		exit(-1);
	}
	free(sha_ctx);
    
    if (memcmp(recv_sha, sha1, 20) != 0)
    {
    	printf("\n\tHASH NON VALIDO\n");
        exit(1);
    }
    free(sha1);

    numblocchi=quanti/16;

     memset(zero, 0, 16);
    p=malloc(sizeof(unsigned char*)* numblocchi );
 #pragma omp parallel for num_threads ( NUMERO_TH_TEST )
    for (int z=1; z<numblocchi; z++) {
        p[z]=malloc(16);
        //l'ultimo carattere mi dice se completato..
    }
    ciphertext=malloc(sizeof(unsigned char*)*numblocchi);
    ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
    EVP_CIPHER_CTX_init(ctx);
    outlen=0;
    L=malloc(16);
    /* Context setup for encryption */
    EVP_EncryptInit(ctx, EVP_aes_256_ecb(), key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, L, &outlen, (unsigned char*)zero, 16);
    if (!EVP_EncryptFinal(ctx, L+outlen, &outlen)) { // se == 0 -> errore
     	printf("Errore in EVP_EncryptFinal\n");
    	exit(-1);
	}
	EVP_CIPHER_CTX_cleanup(ctx);
	EVP_CIPHER_CTX_free(ctx);
    
   
  
    memset(zero, 0, 16);
    zero[15]=1;
    for (int i=0; i<16; i++)
        L[i]|=zero[i];
    calcolaLI(numblocchi, L, p,index);
    char carry=0;
    char ris;
#pragma omp parallel for private(ctx, outlen, carry,ris) num_threads ( NUMERO_TH_TEST )
    for (int i=0;i<numblocchi ; i++) { //fa il cipher
      
        for(int z=0;z <16;z++){
            ris = msg[i*16+z]&127 || p[i][z]&127;
            msg[i*16+z]+= p[i][z] + carry;
            if (ris==1 && (msg[i*16+z]&127)==0)
                carry=1;
            else
                carry=0;
            }
        ciphertext[i]=malloc(16);
        carry=0;
            ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
            EVP_CIPHER_CTX_init(ctx);
            outlen = 0;
            EVP_EncryptInit(ctx, EVP_aes_256_ecb(), key, NULL);
            EVP_CIPHER_CTX_set_padding(ctx, 0);
            EVP_EncryptUpdate(ctx, ciphertext[i], &outlen, &msg[i*16], 16);
            if (!EVP_EncryptFinal(ctx, ciphertext[i]+outlen, &outlen)) { // se == 0 -> errore
            	printf("Errore in EVP_EncryptFinal\n");
            	exit(-1);
			}
            EVP_CIPHER_CTX_cleanup(ctx);
			EVP_CIPHER_CTX_free(ctx);
     
    }
 
       memset(zero, 0, 16);
    for (int i=0;i<numblocchi ; i++) { //xor tra i cipher calcolati
        for(int z=0;z <16;z++)
            zero[z]^=ciphertext[i][z];
            
        }
    char x='a';
    ret=send(sk,(void*)&x,sizeof(char),0);//mando risultato
    if (ret ==-1)
    {
        printf ("errore nel mandare comando e' il mex d'uscita");
        exit(1);
    }
    ret=send(sk,(void*)zero,16,0);//mando risultato
    if (ret ==-1)
    {
        printf ("errore nel mandare comando e' il mex d'uscita");
        exit(1);
    }
    printf("finito un job\n");
    free(msg);
    free(zero);
    for (int i=0; i<16; i++) {
        free(p[i]);
    }
    free(p);
    
}






void tastiera()

{
    char s[50];
    scanf("%s",s);
   if(strcmp(s,"!quit")==0)
   {
       quit();
   }
    else
        printf("comando non riconosciuto\n");
    fflush(stdin);
}
int main(int quantiparametri,char* arg[])
{
    int i;
    int scaduto;  //per il timer
    long ret;
    int quanti=omp_get_num_procs();
    if (quantiparametri != 3)
    {
        printf ("devi passare 2 parametri : ip e porta \n");
        exit(1);
    }		
    help();
    connectserver(arg[1],arg[2]);
        ret=send(sk,(void*)&quanti,sizeof(int),0);  //gli mando prima quanto e' grande l'utente
        if (ret ==-1)
        {
            printf ("errore send numcores");
            exit(1);
        }
    printf ("connessi\n");
    help();
    FD_ZERO(&master);	//azzero master
    FD_ZERO(&read_fd);
    FD_SET(sk,&master);   //setto server
    FD_SET(0,&master);		//setto 0 per tastiera
   
        maxfd=sk;

    
    for (;;)
        
    {
        read_fd=master;  //perche la select mi 'danegerebbe' master
        fflush(stdout);
        scaduto=select(maxfd+1, &read_fd, NULL, NULL, NULL);
        if (scaduto==-1)
        {
            printf("errrore select\n");
            exit(1);
        }
       // printf("evento");
        for (i=0; i<=maxfd;i++)
        {	
            if(FD_ISSET(i, &read_fd))
            {
                if (i==0) //tastiera
                {
                    tastiera();	
                    
                }
                else
                if (i==sk) //mex dal server		
                    mexserver();
                
            }
        }
    }
    return 0;
}
