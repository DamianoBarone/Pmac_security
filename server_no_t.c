#define MAX_CONNESSIONI 1000
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/select.h>

#define fixKey "12345678901234567890123456789012"



//!upload /Users/Damiano/if.c 12345678901234567890123456789012
//!upload /Users/Damiano/bechini.zip 12345678901234567890123456789012
//!upload /Users/Damiano/filetest/1K.txt 12345678901234567890123456789012
struct sockaddr_in my_addr, cl_addr;    // socket server e socket client
int sk, cn_sk; // sk per ascolto
char joball='F';
char* mexprecedente;
struct job
{
    int id;
    char * url;
    unsigned char  cipher[16];
    long size;
    unsigned char *key;
    char occupato;
    struct job * next;
    int numblocchi;
    long numclient;//mi segno il numero di client che gli do il mio lavoro
};
struct job* listajob;
int idglobale=0;
char comandi[6][12]={"!help","!upload","!run","!runall","!quit","!nclients"};
int numeroCoresLiberi=0;
struct clienti * urgentjob;
struct clienti * momentanea;

struct clienti
{
    unsigned long indirizzo; //ip
    struct clienti* next;
    int sock;
    int numero_blocchi;
    int idjob;
    int index;
    int ncores;
    char stato;			//libero o occupato
    int primaistruzione;
};
struct clienti* listaclienti;
fd_set 	master,				//i descittori
read_fd;			 // fd di appoggio per la select
int		maxfd;
void startjob();
void help()
{
    printf("Sono disponibili i seguenti comandi:\n * !help --> mostra l'elenco dei comandi disponibili\n * !nclients --> mostra l'elenco dei client connessi al server\n * !upload url key --> carica un nuovo lavoro dal file url con chiave key\n * !quit --> disconnette il server\n * !run --> esegue solo il primo job nella lista\n * !runall --> esegue tutti i job nella lista\n\n\n\n");
    
}
void print_bytes(const unsigned char* buf, int len) {
    int i;
    for (i = 0; i < len - 1; i++)
        printf("%02X:", buf[i]);
    printf("%02X", buf[len - 1]);
}

void crushclient(struct clienti* elemento )
{
    printf("crushcliente()\n");
    struct clienti* supporto=listaclienti;
    if (elemento==listaclienti)		//estraggo da lista
        listaclienti=elemento->next;
    else
    {
        while (supporto->next!=elemento)
            supporto=supporto->next;
        supporto->next=elemento->next; //supporto e' il precedente di elemento
    }
    if (close(elemento->sock)==0)
        printf("chiusura riuscita del client crasciato\n");
    else
    {
        printf("errore chiusura\n");
        exit(1);
    }
    printf("sock crushato %d\n",elemento->sock);
    FD_CLR(elemento->sock, &master);
    struct clienti * supp=urgentjob;
    if(elemento->stato=='F')//avevo un job
    {
        if(!supp)
        {
            urgentjob=elemento;
            elemento->next=0;
        }
        else
        {
            while(supp->next)
                supp=supp->next;
            supp->next=elemento;
            elemento->next=0;
        }
   
    }
    else
    {
        numeroCoresLiberi-=elemento->ncores;
        free(elemento);
    }

}
void startjob()
{

    FILE* file;
    long ret;
    int index=0;
    char* buf;
    long numBlocchiTotali;
    int caricoSistema,restoblocchi;//numblocchi e' il carico del sistema es val=2 vuole dire 2*numcores
    unsigned char * substring;
    if ((!numeroCoresLiberi || (urgentjob==NULL && listajob==NULL) || listaclienti==NULL))
    {
        
        printf("non ci sono job da elaborare oppure non ci sono clienti disponibili\n");
        return;
    }
    struct job * suppjob;
    suppjob=listajob;
    if(urgentjob!=NULL)
    {// printf("siamo in urgent\n");
        while(suppjob)
        {
            if(suppjob->id== urgentjob->idjob)
                break;
            else
                suppjob=suppjob->next;
        }
        if(suppjob==0)
            return;
        suppjob->numclient--;//perche era rimasto incrementato
        caricoSistema=urgentjob->numero_blocchi/numeroCoresLiberi;
        restoblocchi=urgentjob->numero_blocchi%numeroCoresLiberi;
   

        file = fopen(suppjob->url, "r");
        if(file == NULL) {
            printf("\nFile not found: %s\n", suppjob->url);
            return;
        }
        fseek(file, (urgentjob->index*16), SEEK_SET);
        buf=malloc(urgentjob->numero_blocchi*16);
        fread(buf, urgentjob->numero_blocchi*16, 1, file);
        numBlocchiTotali=urgentjob->numero_blocchi;
        index=urgentjob->index;

    }
    else
    {
        int num_read;
        while(suppjob)
        {
            if(suppjob->occupato=='F')
            {
                break;
            }
            else
            {
                suppjob=suppjob->next;

            }
    
        }
        
        if(suppjob==0)//non so se devo mettere null
        {
            printf("non ci sono job da elaborare");
            return; //non e' stato trovato nessun job da eseguire
        }

        suppjob->numclient=0;
        caricoSistema=suppjob->numblocchi/numeroCoresLiberi;
        restoblocchi=suppjob->numblocchi%numeroCoresLiberi;

        file = fopen(suppjob->url, "r");
        if(file == NULL) {
            printf("\nFile not found: '%s'\n", suppjob->url);
            return;
        }
        buf=malloc(suppjob->numblocchi*16);
        num_read=fread(buf, 1, suppjob->numblocchi*16, file); //FARE SOLO SE NON E' URGENT
        numBlocchiTotali=suppjob->numblocchi;
        

    }
    //in comune hai i due casi
    
    struct clienti * cliente=listaclienti;
    long quanti;
   
    while(cliente)
    {
        if (numBlocchiTotali<1)
            break;
        
        if (cliente->stato!='F')
        {
            //mando i blocchi tramite numblocchi e resto blocchi se e' con urgentjob devo mandare dal index preso da urgentjob
            quanti= cliente->ncores*caricoSistema;
            if (restoblocchi) {
                if(restoblocchi>=cliente->ncores)
                {
                    quanti+=cliente->ncores;
                    restoblocchi-=cliente->ncores;
                }
                else
                {
                    quanti+=restoblocchi;
                    restoblocchi=0;
                }
            }
            cliente->stato='F';
            suppjob->numclient++;
            numBlocchiTotali-=quanti;
            cliente->numero_blocchi=quanti;
            cliente->idjob=suppjob->id;
            quanti*=16;
            substring=malloc(quanti);
            memcpy( substring, &buf[index*16], quanti);
                        // calcolo hash
            char *sha1=malloc(20);
            SHA_CTX *sha_ctx=(SHA_CTX *)malloc(sizeof(SHA_CTX));
			if (!SHA1_Init(sha_ctx)) {
				perror("sha init error\n");
				exit(-1);
			}
			if (!SHA1_Update(sha_ctx, (unsigned char*)suppjob->key, 32)) {
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
			if (!SHA1_Update(sha_ctx, (unsigned char*)substring, quanti)) {
				perror("sha update error\n");
				exit(-1);
			}
			if (!SHA1_Final(sha1, sha_ctx)) {
				perror("sha final error\n");
				exit(-1);
			}
			free(sha_ctx);
            
            
        	// cifratura key e hash 
        	char *key_sha=malloc(64); // 52 + 12
        	EVP_CIPHER_CTX* ctx_key=(EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
			EVP_CIPHER_CTX_init(ctx_key);
			int outlen=0, outlen2=0;
			/* Context setup for encryption */
			EVP_EncryptInit(ctx_key, EVP_aes_256_cbc(), fixKey, NULL);
			EVP_EncryptUpdate(ctx_key, key_sha, &outlen, (unsigned char*)suppjob->key, 32);
			EVP_EncryptUpdate(ctx_key, key_sha+outlen, &outlen2, (unsigned char*)sha1, 20);
			if (!EVP_EncryptFinal(ctx_key, key_sha+outlen+outlen2, &outlen)) { // se == 0 -> errore
				printf("Errore in EVP_EncryptFinal\n");
				exit(-1);
			}
			EVP_CIPHER_CTX_cleanup(ctx_key);
			EVP_CIPHER_CTX_free(ctx_key);
            ret=send(cliente->sock,(void*)key_sha,64,0);//mando key
            if (ret ==-1)
            {
                printf ("errore nel mandare comando e' il mex d'uscita1\n");
                exit(1);
            }
            free(sha1);
            free(key_sha);
            ret=send(cliente->sock,(void*)&index,sizeof(int),0);//mi seve per fare la p
            if (ret ==-1)
            {
                printf ("errore nel mandare comando e' il mex d'uscita4\n");
                exit(1);
            }
           ret=send(cliente->sock,(void*)&quanti,sizeof(long),0);//mando lunghezzasubstring
            if (ret ==-1)
            {
                printf ("errore nel mandare comando e' il mex d'uscita2\n");
                exit(1);
            }
            
            
         ret=send(cliente->sock,(void*)substring,quanti,0);//mando stringa da cifrare il client deve controllare lunghezza se %128 per il padding
            if (ret ==-1)
            {
                printf ("errore nel mandare comando e' il mex d'uscita3\n");
                exit(1);
            }
           
            numeroCoresLiberi-=cliente->ncores;

        }
        cliente->index=index;
        index+=cliente->numero_blocchi;
        
        cliente=cliente->next;
    }
    if(urgentjob)
        urgentjob=urgentjob->next;
        
    
    fclose(file);
    free(substring);
    return;

}
void newjob()
{
    char word[100];
    char* url;

    unsigned char*key;
    struct job*  nuovojob; //creo il nuovo utente
    scanf("%[^\n]s", word);
    url = strtok (word, " ");
    key= strtok(NULL, " ");


    
    if(strtok(NULL, " ") != NULL || url==NULL || key==NULL){
        printf("devi mettere 2 argomenti\n");
        return;
    }
    if (strlen(key)!=32) {
        printf("la key deve essere lunga 32 caratteri");
        return;
    }
    nuovojob= malloc(sizeof (struct job));
    nuovojob->url=malloc(strlen(url)+1);
    nuovojob->url[strlen(url)]=0;
    strncpy(nuovojob->url, url,strlen(url) );
    nuovojob->key=malloc(32);
    memcpy(nuovojob->key, key, 32);
    nuovojob->id=idglobale;
    nuovojob->occupato='F';
    memset(nuovojob->cipher,0,16);
    idglobale++;
    FILE* file = fopen(url, "r");
    if(file == NULL) {
        printf("\nFile not found: '%s'\n", word);
        return;
    }
    fseek(file, 0, SEEK_END);
    long size =ftell(file);
    fseek(file, 0, SEEK_SET);
    
    nuovojob->size=size;
    nuovojob->next=0;
    long mancanti=nuovojob->size%16;//se diverso da zero c'e' il padding
    if(mancanti!=0)//faccio padding
    {
        fseek(file, size-(mancanti),SEEK_SET);
        fread(&(nuovojob->cipher[16-mancanti]), 1, mancanti, file);
        printf("hai il padding ");
        for (int i=0;i<16-mancanti;i++)
        {
            if(i<mancanti-1)
                nuovojob->cipher[i]=0;//controllare se questa parte piu significativa*****
            else
                if(i==mancanti)
                    nuovojob->cipher[i]=1;
            
        }
       
    }
    else
    {
        fseek(file, size-(16),SEEK_SET);
        fread((nuovojob->cipher), 1, 16, file);
    }
    

    nuovojob->numblocchi=size/16;
    if(nuovojob->size%16==0)
        nuovojob->numblocchi--;
    fclose(file);
    if (listajob==NULL)
    {
        listajob=nuovojob;
    }
    else
    {
        struct job* supp=listajob;
        while (supp->next) {
            supp=supp->next;
        }
        supp->next=nuovojob;
    }
    printf("job caricato se vuoi eseguirlo puoi scrivere !run\n");

}
void quit()
{
    printf("quit()\n");
    exit(1);
}
void startjoball()
{
    if (!(!numeroCoresLiberi || (urgentjob==NULL && listajob==NULL) || listaclienti==NULL))
    {
        joball='T';
        startjob();
        
    }
   else
       printf("non ci sono piu job oppure  clients");
    return;
}
void numclients()
{
    struct clienti * supp=listaclienti;
    int count=0;
    int numerocores=0;
    while (supp!=NULL) {
        count++;
        numerocores+=supp->ncores;
        supp=supp->next;
        
    }
    printf("numero di client connessi %d\n",count);
    printf("numero di core connessi %d\n",numerocores);

    //fare pure client disponibili
}

void tastiera()//per adesso considera solo gli url carica, ma si puo mettere run e numero clientis
{
    char s[30];
    int i;
    scanf("%s",s);
    for (i=0;i<6;i++)
    {
        if (strcmp(s,comandi[i])==0)
        {
            break;
        }
        
    }
    switch(i){
            
        case 0:
            help();
            break;
        case 1:
            newjob();
            break;
        case 2:
            startjob();
            break;
        case 3:
            startjoball();
            break;
        case 4:
            quit();
            break;
        case 5: 
            numclients();
            break;
        default:
            printf("comando non riconosciuto\n");
    }
 
    //upload e' la parola chiave
    
    
}
void connessione(char* ip, char* porta)
{
    int ret;
    int yes = 1;
    sk = socket(AF_INET, SOCK_STREAM, 0);   //tcp
    if (setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
        perror("setsockopt");
        exit(1);
    }
    if (sk==-1)
    {
        printf("errore nel creare socket\n");
        exit(1);
    }
    
    memset(&my_addr, 0, sizeof(my_addr));  	//azzero la struttura
    my_addr.sin_family = AF_INET;  			// famiglia ipv4
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY); // formato di rete
    my_addr.sin_port = htons(atoi(porta));				//porta
    ret = bind(sk, (struct sockaddr*) &my_addr, sizeof(my_addr));	//Collega un indirizzo locale al socket creato con la socket
    if(ret==-1)
    {
        printf("errore bind\n");
        exit(1);
    }
    ret = listen(sk, MAX_CONNESSIONI);    			// in attesa di richieste
    if(ret==-1)
    {
        printf("errore listen");
        exit(1);
    }
}






void aggiungicliente(struct clienti* nuovocliente)   //ricevo numero core
{
    long ret;
    int numerocores;
    ret=recv(nuovocliente->sock,(void*)&numerocores,sizeof(int),MSG_WAITALL);  // numero core
    
    if(ret ==-1)
    {
        printf("errore ricevuti quanti\n");
        exit(1);
    }
    if(ret ==0)
    {
        crushclient(nuovocliente);
    }
    else
    {
        nuovocliente->ncores=numerocores;
        numeroCoresLiberi+=numerocores;
    nuovocliente->stato='L';
        
    }
    nuovocliente->primaistruzione=1;
    struct clienti* precedente = NULL; //metto nella lista il nuovo utente
    struct clienti* supporto;
    supporto=momentanea;
    while(supporto!=nuovocliente)
    {
        precedente=supporto;
        supporto=supporto->next;
        
    }
    if(supporto==momentanea)
        momentanea=supporto->next;
    else
        precedente->next=supporto->next;
    
    
    
    precedente=listaclienti;
    if (listaclienti==0) // nessun cliente
    {
        listaclienti=nuovocliente;
        nuovocliente->next=NULL;
    }
    else
    {
        
        while (precedente && nuovocliente->ncores < precedente->ncores)
        {
            supporto=precedente;
            precedente=precedente->next;
        }
        if (precedente==listaclienti)
        {
            nuovocliente->next=listaclienti;
            listaclienti=nuovocliente;
        }
        else
        {
            supporto->next=nuovocliente;
            nuovocliente->next=precedente;
        }
        
    }
    
    
}
void final (struct job* job) //conto se c'e' stato il padding
{

    
    EVP_CIPHER_CTX* ctx;            //serve per trovare la L
    unsigned char L[16];
    unsigned char zero[16];
    memset(zero, 0, 16);
    ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
    EVP_CIPHER_CTX_init(ctx);
    int outlen=0;
    /* Context setup for encryption */
    EVP_EncryptInit(ctx, EVP_aes_256_ecb(), job->key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, L, &outlen, (unsigned char*)zero, 16);
    if (!EVP_EncryptFinal(ctx, L+outlen, &outlen)) { // se == 0 -> errore
     	printf("Errore in EVP_EncryptFinal\n");
    	exit(-1);
	}
	EVP_CIPHER_CTX_cleanup(ctx);
	EVP_CIPHER_CTX_free(ctx);
    zero[15]=1;
    char carry=0;
    char ris;
    for (int i=0; i<16; i++)
    {
      
        L[i]|=zero[i];
        L[i]=~L[i];//complemento
    }
    for (int i=0; i<16; i++) {
        
        ris = L[i]&127 || job->cipher[i]&127;
        //p[z][j]+= l[j] + carry;
        job->cipher[i]+=L[i]+carry;
        if (ris==1 && (job->cipher[i]&127)==0)
            carry=1;
        else
            carry=0;
    }

    

    
}

void calcolofinale(struct job* job)
{

    EVP_CIPHER_CTX* ctx;
    unsigned char* risultato=malloc(16);
    int outlen;
    if (!(job->size%16))//se e' multiplo di 16 fare final
        final(job); //mi cambia il job->cipher emette il final
    ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
    EVP_CIPHER_CTX_init(ctx);
    outlen=0;
    EVP_EncryptInit(ctx, EVP_aes_256_ecb(), job->key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, risultato, &outlen, (unsigned char*)job->cipher, 16);
    if (!EVP_EncryptFinal(ctx, risultato+outlen, &outlen)) { // se == 0 -> errore
     	printf("Errore in EVP_EncryptFinal\n");
    	exit(-1);
	}

	EVP_CIPHER_CTX_cleanup(ctx);
	EVP_CIPHER_CTX_free(ctx);
    printf("risultato finale del file %s\n",job->url);
    printf(" MAC : ");
    print_bytes(risultato, 16);
    printf("\n");
    struct  job* s=job;
    listajob=listajob->next;//facendo cosi pero' non funzionera se ci sono piu job in parallelo
    free(s->url);
    free(s->key);
    free(s);
    

}

void risultatoclient(struct clienti* elemento)
{
   // printf("rispostacliente()\n");

    char cipher[16];
    long ret;
    ret=recv(elemento->sock,(void*)&cipher, 16,MSG_WAITALL);//ricevo il cipher
    if(ret==-1)
    {
        printf("errore nel ricevere dati\n");
        exit(1);
    }
    if (ret!=16 || ret==0)
    {
        printf("errore recv cipher dal client %ld",ret);
    }
    //print_bytes(cipher, 16);
    // printf("del client %d\n",elemento->sock);
    struct job* suppjob=listajob;
    while(suppjob)
    {
        if(elemento->idjob==suppjob->id)
            break;
        else
            suppjob=suppjob->next;
    }
    if (suppjob==NULL)
    {    printf("errore nella ricezione del client, non conosco questo client\n");
        exit(1);
    }
    suppjob->numclient--;
    for (int i=0; i<16; i++) {
        suppjob->cipher[i]^=cipher[i];
    }
    numeroCoresLiberi+=elemento->ncores;//aggiorni i core disponibili
    elemento->stato='L';
    if(!suppjob->numclient)
    {
        calcolofinale(suppjob);
        if ( joball=='T')
            startjob();
        else
            joball='F';
    }
    if (urgentjob) //nel caso c'e' qualcuno disponibile
        startjob();
    
	
	
	return ;
}

void gestioneclienti(struct clienti* elemento)
{
    long ret;
    char msg;
    ret=recv(elemento->sock,(void*)&msg, sizeof(char),0);
    if(ret==-1)
    {
        printf("errore nel ricevere dati\n");
        exit(1);
    }
    if(ret==0)
    
        crushclient(elemento);
    
    else
        risultatoclient(elemento);
    
}




int main(int quantiparametri,char* arg[])
{
    int len;
    int i;
    unsigned int porta;
    FD_ZERO(&master);	//azzero fd
    FD_ZERO(&read_fd);
    if (quantiparametri != 3)
    {
        printf ("devi passare 2 parametri : ip e porta\n");
        exit(1);
    }
    porta=atoi(arg[2]);
    if (porta>65535 || porta<1024)
    {
        printf("errore porta\n");
        exit(1);
    }		
    connessione(arg[1],arg[2]);
    FD_SET(sk,&master); // setto il socket che voglio controllare
    FD_SET(0,&master);		//setto 0 per tastiera
    help();
    maxfd=sk; // per ora e' il massimo
    for(;;)
    {
        read_fd=master;  //perche la select mi 'danegerebbe' master
        fflush(stdout);
        fflush(stdin);

        if(select(maxfd+1, &read_fd, NULL, NULL, NULL) == -1)
        { 
            printf("errore nella select!");
            exit(1);
        }
        for ( i=0; i<=maxfd;i++)
        {	
            if(FD_ISSET(i, &read_fd))
            {
                if (i==sk)   // un client si vuole connettere, quindi lo devo accettare
                {	
                    len = sizeof(cl_addr);	
                    cn_sk = accept(sk, (struct sockaddr*) &cl_addr,(socklen_t *) &len); // richiesta accettata presa dal listening del socket, cn_sk ha la conessione mi servira per send e receive
                    if(cn_sk==-1)
                    {
                        printf("errore di accettazione\n");
                        exit(1);
                    }
                    FD_SET(cn_sk,&master);
                    if(cn_sk> maxfd)
                        maxfd=cn_sk;
                    printf("nuova connessione %d\n",cn_sk);
                    struct clienti* nuovocliente; //creo il nuovo utente
                    nuovocliente= malloc(sizeof (struct clienti));
                    int length = sizeof(cl_addr);
                    memset(&cl_addr, 0, length);
                    getpeername(cn_sk, (struct sockaddr *)&cl_addr, (socklen_t *)&length); //trovo l'indirizzo del client che si e' connesso
                    nuovocliente->sock=cn_sk;
                    nuovocliente->next=0;//DEVE AGGIUNGERE IN MANIERA ORDINATA
                    nuovocliente->stato='F'; //occupato per adessossss
                    nuovocliente->primaistruzione=0;
                    nuovocliente->indirizzo = cl_addr.sin_addr.s_addr; //indirizzo
                    nuovocliente->next=momentanea;
                    momentanea=nuovocliente;
                }
            else//e' un client gia noto oppure e quello che deve fare i vari salti per registrarsi
                {
                    
                    if (i==0)//tastiera
                        tastiera();
                    else
                    {
                        struct clienti* elemento=listaclienti;
                        while(elemento!=0)
                        {
                            if (elemento->sock==i)    //elemento trovato
                                break;
                            elemento=elemento->next;
                        }
                        if (elemento==0)
                        {
                            elemento=momentanea;
                            while(elemento!=0)
                            {
                                if (elemento->sock==i)    //elemento trovato
                                    break;
                                elemento=elemento->next;
                            }
                                aggiungicliente(elemento);
                        }
                        else
                        gestioneclienti(elemento);
                    }
                    
                }
            }	
        }
    }
    return 0;
}

