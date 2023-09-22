#include <netinet/ether.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/time.h>
#include <netdb.h>

#define MAXLINE 512
#define HEADER_LEN 12
#define QUERY_HEAD_LEN 4
#define ANSW_ENTRY_LEN 10
#define QR 0x8000
#define OPCODE 0x7800
#define AA 0x400
#define TC 0x200
#define RD 0x100
#define RA 0x80
#define Z 0x70
#define RCODE 0xF

// hlavička dns packetu, identifikátor, control = příznaky, x_count počet záznamů v jednotlivých sekcích
struct dns_header {
	u_short identification;
	u_short control;
	u_short q_count;
	u_short a_count;
	u_short auth_count;
	u_short add_count;
};

// struktura záznamu (RR) bez dns name, které má variabilní délku
struct dns_answ_entry {
	u_short rr_type;
	u_short class;
	u_int ttl;
	u_short rdata_len;
};

// struktura záznamu dotazu
struct dns_q_entry {
	u_short rr_type;
	u_short class;
};

struct SOA_record {
	int serial;
	int refresh;
	int retry;
	int expire;
	int minimum;
};

// mystrlen, který počítá délku stringu podobně jako strlen, s rozdílem přestání počítání délky i na "odkazu" v dns name
int mystrlen(char* mystring){
	int len = 0;
	int i = 0;
    while (mystring[i] != 0){
        len++;
		// printf("%02x",mystring[i]);
		if((mystring[i]&0x40)&&(mystring[i]&0x80))				//((unsigned char)mystring[i])>191
			return len;
		i++;
    }
    return len;
}

// transformace dns dotazu s tečkami na dns dotaz v komprimovaném formátu
void to_dns_format(char* old_name,char* result_name)
{
	int len = strlen(old_name);

	int k =0;
	result_name[len+1]=0;
	
	for(int i = len-1 ; i>=0 ; i--){
		if(old_name[i]=='.'){
			result_name[i+1]=k;
			k=0;
		} else {
			result_name[i+1]=old_name[i];
			k++;
			if(i==0)
				result_name[i]=k;
		}
	}
}

// transformace záznamu z komprimovaného formátu
void from_dns_format(unsigned short int iterator,char *buffer)
{
	if(!(buffer[iterator]&0x40)&&(buffer[iterator]&0x80))
		iterator++;
	
	for(;; iterator++){
		if(buffer[iterator]<40){
			if(buffer[iterator]==0)
				return;
			
			if ((buffer[iterator]&0x40)&&(buffer[iterator]&0x80)) {
				from_dns_format(ntohs(*((unsigned short*)&buffer[iterator]))-0xC000,buffer);
				return;
			}
			printf(".");
		} else {
			printf("%c",buffer[iterator]);
		}
	}
}

// výpis typu záznamu (transformace z čísla na zkratku)
void resolv_rrtype(unsigned short rrtype)
{
	switch (rrtype)
	{
		case 1:
			printf("A\t");
			break;
		case 2:
			printf("NS\t");
			break;
		case 5:
			printf("CNAME\t");
			break;
		case 6:
			printf("SOA\t");
			break;
		case 12:
			printf("PTR\t");
			break;
		case 15:
			printf("MX\t");
			break;
		case 16:
			printf("TXT\t");
			break;
		case 25:
			printf("KEY\t");
			break;
		case 28:
			printf("AAAA\t");
			break;
		case 35:
			printf("NAPTR\t");
			break;
		case 39:
			printf("DNAME\t");
			break;
		case 43:
			printf("DS\t");
			break;
		case 46:
			printf("RRSIG\t");
			break;
		case 48:
			printf("DNSKEY\t");
			break;
		default:
			printf("neznámý rr_type %d\t",rrtype);
	}
}

// výpis třídy záznamu (transformace z čísla na zkratku)
void resolv_class(unsigned short qclass)
{
	switch (qclass)
	{
		case 1:
			printf("IN\t");
			break;
		case 2:
			printf("Unassigned\t");
			break;
		case 3:
			printf("CH\t");
			break;
		case 4:
			printf("HS\t");
			break;
		case 254:
			printf("NONE\t");
			break;
		case 15:
			printf("ANY\t");
			break;
		default:
			printf("neznámá class %d\t",qclass);
	}
}

// výpis dat záznamu s využitím typu záznamu. 
void resolv_rdata(char * rdata, short rdata_len, short rr_type,char * buffer,unsigned short int iterator)
{
	char tmp_string[INET6_ADDRSTRLEN];
	switch (rr_type)
	{
		case 1:
			printf("%s",inet_ntop(AF_INET,rdata,tmp_string,INET6_ADDRSTRLEN));	// A
			break;
		case 28:
			printf("%s",inet_ntop(AF_INET6,rdata,tmp_string,INET6_ADDRSTRLEN));	// AAAA
			break;
		case 2:
		case 5:
		case 12:
		case 15:
		case 39:
			from_dns_format(iterator+1,buffer);		//NS,CNAME,SOA,PTR,MX,DNAME
			break;
		case 6:
			for(int i=iterator;i<iterator+30;i++){
				printf("%x ",buffer[i]);
				}
			from_dns_format(iterator,buffer);
			printf("\n");
			iterator+=mystrlen(&buffer[iterator])+1;
			from_dns_format(iterator,buffer);
			printf("\n");
			iterator+=mystrlen(&buffer[iterator+1])+1;
			struct SOA_record soa_record = *((struct SOA_record*) &buffer[iterator]);
			printf("%d\n%d\n%d\n%d\n%d\n",ntohl(soa_record.serial),ntohl(soa_record.refresh),ntohl(soa_record.retry),ntohl(soa_record.expire),ntohl(soa_record.minimum));
			break;
		case 16:
		case 25:
		case 35:
		case 43:
		case 46:
		case 48:
			for(int i = 0;i<rdata_len;i++)	//other
			{
				printf("%c",rdata[i]);
			}
			break;
		default:
			printf("neznámý rr_type\n");
	}
	printf("\n");
}

// transformuje ip, otočí pořadí, přidá doménu na konec a změní tečky na správné čísla
void transform_ip_to_dns(char * query_string,char *dnsname,char ip6_query)
{
	
	char tmp_query_string[strlen(query_string)+15];
	strcpy(tmp_query_string,query_string);
	char *token;

	int q_len = strlen(tmp_query_string)+1;

	
	if(ip6_query){
		int cursor = 0;
		char ip6_struc[16];
		if(inet_pton(AF_INET6,query_string,ip6_struc)==0){
			printf("Špatně zadaná IPv6 adresa!!!!\n");
			exit(1);
		}
		for(int i=15;i>=0;i--){
			char c=ip6_struc[i];
			
			dnsname[cursor]=1;
			cursor++;
			dnsname[cursor]=(c&0xF)+48;
			if(dnsname[cursor]>57)
				dnsname[cursor]+=39;
			cursor++;
			dnsname[cursor]=1;
			cursor++;
			dnsname[cursor]=(c>>4)+48;
			if(dnsname[cursor]>57)
				dnsname[cursor]+=39;
			cursor++;

		}
		strcpy(&dnsname[cursor],"\003ip6\004arpa");
		// printf("%s",dnsname);
		return;
	}
	
	struct in_addr tmp_addr;
	if(inet_pton(AF_INET,query_string,&tmp_addr)==0){
			printf("Špatně zadaná IP adresa!!!!\n");
			exit(1);
		}
		
		
	strcpy(&dnsname[q_len],"\007in-addr\004arpa");

	token = strtok(tmp_query_string, ".");
	
	
	while( token != NULL ) {
		
		dnsname[q_len - strlen(token) - 1]=strlen(token);
		char tmp = dnsname[q_len];
		strcpy(&dnsname[q_len - strlen(token)],token);
		dnsname[q_len]=tmp;
		
		q_len = q_len - strlen(token) - 1;
		
		token = strtok(NULL, ".");
	}
	
	//printf("dnsname[0]:%d dnsname: %s\n\n",dnsname[0],dnsname);
}

void print_help()
{
	printf("spuštění:\n");
	printf("./dns dns [-r] [-x] [-6] -s server [-p port] adresa, kde význam parametru je následující: \n");
	printf("* -r: Určuje, zda chceme požádat o rekursivní dotaz (nastavuje flag RD).\n");
	printf("* -x: Určuje, že chceme využít reversní dotaz, předpokládá v adrese IP adresu.\n");
	printf("* -6: Místo výchozího A dotazu se ptáme na AAAA. V kombinaci s -x určujeme, že zadaný argument <adresa> bude IPv6 adresa.\n");
	printf("* -s <server>: Nutný argument, na který dns server máme dotaz posílat, možné zadat jak doménové jméno tak IP adresu.\n");
	printf("* -p <port>: Zbytečný argument, který udává přes jaký port chceme komunikovat, kažopádně server na jiný, než výchozí port 53 neodpovídá.\n");
	printf("* <adresa>: Jméno, případně IP, na které se chceme dotázat.\n");
}

void print_section(unsigned short int *iterator,char*buffer)
{
	printf(" ");
	from_dns_format(*iterator,buffer);
	printf("\t");
	*iterator += mystrlen(&buffer[*iterator])+1;


	struct dns_answ_entry answ_entry = *((struct dns_answ_entry*) &buffer[*iterator]);
	*iterator += ANSW_ENTRY_LEN;
	answ_entry.rdata_len = ntohs(answ_entry.rdata_len);
	resolv_rrtype(ntohs(answ_entry.rr_type));
	resolv_class(ntohs(answ_entry.class));
	printf("%d\t",ntohl(answ_entry.ttl));
		
	
	int rdata_size = 0;
	if(answ_entry.rr_type==2||answ_entry.rr_type==5||answ_entry.rr_type==6||answ_entry.rr_type==15||answ_entry.rr_type==39){
		rdata_size = mystrlen(&buffer[*iterator]);
	} else {
		rdata_size =answ_entry.rdata_len;
	}
	char rdata[rdata_size+1];
	strncpy(rdata,&buffer[*iterator],rdata_size-1);
	
	resolv_rdata(rdata,answ_entry.rdata_len,ntohs(answ_entry.rr_type),buffer,*iterator);
	*iterator += rdata_size;//answ_entry.rdata_len;
}

int main(int argc, char* argv[])
{

	printf("\n\n");
	if(argc<4){
		printf("očekávaný minimální počet argumentů je: 3, argc = %d, %s\n", argc-1,argv[0]);
		print_help();
		return 1;
	}
	unsigned short recursion = 0;
	char reverze = 0;
	char ip6_query = 0;
	char server_arg = 0;
	char addr_arg = 0;
	char *dns_server;
	int port = 53;
	char * query_string;
	// PARSOVÁNÍ ARGUMENTŮ
	for ( int i =1 ; i<argc ; i++)
	{
		if(!strcmp(argv[i],"-s"))
		{
			i++;
			if(i<argc){
				server_arg = 1;
				dns_server = argv[i];
			}
			else{
				printf("očekávaný jméno dns serveru za argumentem -s\n");
				print_help();
				return 1;
			}
		} else if(!strcmp(argv[i],"-r"))
		{
			recursion = RD;
		} else if(!strcmp(argv[i],"-x"))
		{
			reverze = 1;
		} else if(!strcmp(argv[i],"-6"))
		{
			ip6_query = 1;
		} else if(!strcmp(argv[i],"-p"))
		{
			i++;
			if(i<argc)
			{
				port = strtol(argv[i],NULL,10);
				if(port<1){
					printf("špatně zadané číslo portu\n");
					return 1;
				}
			}
			else{
				printf("očekávané číslo portu za argumentem -p\n");
				print_help();
				return 1;
			}
		} else
		{
			addr_arg = 1;
			query_string = argv[i];
		}
	}
	if(addr_arg+server_arg!=2)
	{
		printf("nebyly správně zadány nutné argumenty: <-s server> a nebo <adresa>\n");
		print_help();
		return 1;
	}
	// VÝPIS ARGUMENTŮ
	printf("recursion =%d, reverse=%d, AAAA=%d, port=%d\n",ntohs(recursion),reverze, ip6_query, port);
	printf("using server: %s, query on %s\n",dns_server,query_string);
	
	
	// TRANSFORMACE DOTAZOVANÉHO STRINGU NA SPRÁVNÝ FORMÁT
	int q_len = 0;
	char dnsname[255];

	if(reverze)
	{
		transform_ip_to_dns(query_string,dnsname,ip6_query);
	} else {
		to_dns_format(query_string,dnsname);
	}

	q_len = strlen(dnsname)+1;
	
	
	// VYHLEDÁNÍ SERVERU
	struct hostent *remote_host;
    struct in_addr addr;
	int paket_lenght = HEADER_LEN+QUERY_HEAD_LEN+q_len;
	char paket[paket_lenght];
	
	if(inet_pton(AF_INET,dns_server,&addr)||inet_pton(AF_INET6,dns_server,&addr)){
		printf("byla zadaná ip dns serveru %s\n",dns_server);
	} else {

		remote_host = gethostbyname(dns_server);

		if(remote_host==NULL){
			printf("nebyl nalezen dns server: %s, který jste zadali\n",dns_server);
			return 1;
		} else if (remote_host->h_addr_list[0] != 0) {
			addr.s_addr = *(u_long *) remote_host->h_addr_list[0];
			printf("\tIP: %s\n",inet_ntoa(addr));
		} else {
			printf("neznámí problém se zadáním %s serveru\n",dns_server);
			return 1;
		}

	}

	// VYTVOŘENÍ SOCKETU
	socklen_t len;
	int n=0;
	int sockfd;
	char buffer[MAXLINE+1];
	
	struct sockaddr_in servaddr;
	if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("vytváření socketu selhalo\n"); 
        return 1; 
    } 
	// NASTAVENÍ TIMEOUT, pro případ nemožnosti komunikace, aby se program nezasekl
	struct timeval tv;
	tv.tv_sec = 3;
	tv.tv_usec = 0;
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
		printf("nepovedlo se nastavit timeout\n");
		return 2;
	}
	// printf("socket vytvoren\n");
	
	
	memset(&servaddr, 0, sizeof(servaddr)); 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_port = htons(port); 
    servaddr.sin_addr.s_addr = addr.s_addr;
	// printf("vytvoreni struktury adresy pro odeslani\n");
	
	
	// NAPLNĚNÍ DNS HLAVIČKY
	struct dns_header head;
	head.identification = htons(7);
	head.control = htons(0|recursion);
	head.q_count = htons(1);
	head.a_count = htons(0);
	head.auth_count = htons(0);
	head.add_count = htons(0);
	
	// VYTVOŘENÍ DOTAZU
	struct dns_q_entry question;
	question.rr_type = htons(1);
	if(reverze)
		question.rr_type = htons(12);
	else if(ip6_query)
		question.rr_type = htons(28);
	question.class = htons(1);
	
	// NAPLNĚNÍ PACKETU DATY
	printf("sestaven packet v HEX:\n");
	printf("hlavička:\n");
	char * tmphead = (char*)&head;
	for (unsigned int k =0 ; k<12 ; k++)
	{
		paket[k]=tmphead[k];
		printf("%02X ",paket[k]);
	}
	printf("\ndotazovaný řetězec:\n");
	for (unsigned int k = 0 ; k<strlen(dnsname)+1 ; k++)
	{
		paket[k+12]=dnsname[k];
		printf("%02X ",paket[k+12]);
	}
	
	printf("\nqtype a qclass:\n");
	char * tmptail = (char*)&question;
	for (unsigned int k = 0 ; k<4 ; k++)
	{
		paket[k+paket_lenght-4]=tmptail[k];
		printf("%02X ",paket[k+paket_lenght-4]);
	}
	printf("\n");


	// ODESLÁNÍ PACKETU
	sendto(sockfd, (const void *)&paket, paket_lenght,MSG_CONFIRM, (const struct sockaddr *) &servaddr,  sizeof(servaddr)); 

	// PŘIJMUTÍ ODPOVĚDI
	n = recvfrom(sockfd, &buffer, MAXLINE+1,MSG_WAITALL, (struct sockaddr *) &servaddr,&len); 
	if (n<0){
		printf("!timeout nebo jiné odmítnutí komunikace lokálního systému!\n");
		return 2;
	}
	
	// PARSOVÁNÍ ODPOVĚDI
	unsigned short int iterator = 0;
	struct dns_header answ_header = *((struct dns_header*) &buffer[iterator]); // struktura hlavičky packetu
	iterator += HEADER_LEN;
	printf("\n********ANSWER PACKET********\n");
	printf("pocet bytu prijatych: %d\n",n);
	printf("id = %d\nquestion count = %d\nanswer count = %d\nauthorize count = %d\nadditional = %d\n\n",
	ntohs(answ_header.identification),
	ntohs(answ_header.q_count),
	ntohs(answ_header.a_count),
	ntohs(answ_header.auth_count),
	ntohs(answ_header.add_count));
	
	if(!(ntohs(answ_header.control) & QR)){
		printf("bit QR v hlavičce říká, že je to otázka a to by neměla! im out\n");
		return 1;
	}
	ntohs(answ_header.control) & AA ? printf("Authoritative: YES, ") : printf("Authoritative: NO, ");
	ntohs(answ_header.control) & TC ? printf("Truncated: YES, ") : printf("Truncated: NO, ");
	(ntohs(answ_header.control) & RA) && (ntohs(answ_header.control) & RD) ? printf("Recursive: YES") : printf("Recursive: NO");
	printf(", opcode: %d\n",(answ_header.control & OPCODE)>>11);
	// printf("%u CONTROL\n",ntohs(answ_header.control));
	if(ntohs(answ_header.control) & RCODE){
		printf("DNS server answers with error code: %d\n",ntohs(answ_header.control) & RCODE);
		// return 1;
	}
	
	// ***** vypsání HEX celé odpovědi*****
	// for (int i=0;i<n;i++){
	// printf("%02X ", buffer[i]);
	// }
	
	printf("\n* * *  Q U E S T I O N   S E C T I O N * * *\n");
	for(int i = 0; i<ntohs(answ_header.q_count);i++){

		printf("  ");
		from_dns_format(iterator,buffer);	// výpis QNAME
		printf("\t");
		iterator += mystrlen(&buffer[iterator])+1;
		struct dns_q_entry answ_q_entry = *((struct dns_q_entry*) &buffer[iterator]);
		iterator += QUERY_HEAD_LEN;
		
		
		resolv_rrtype(ntohs(answ_q_entry.rr_type));
		resolv_class(ntohs(answ_q_entry.class));
		printf("\n");
	}
	printf("\n* * * * * * A N S W E R   S E C T I O N * * * * * *\n");
	for(int i = 0; i<ntohs(answ_header.a_count);i++){
		
		print_section(&iterator,buffer);
		
	}
	printf("\n* * * * A U T H O R I T Y  S E C T I O N * * * *\n");
	for(int i = 0; i<ntohs(answ_header.auth_count);i++){
		
		print_section(&iterator,buffer);
		
	}
	printf("\n* * *  A D D I T I O N A L   S E C T I O N * * *\n");
	for(int i = 0; i<ntohs(answ_header.add_count);i++){
		
		print_section(&iterator,buffer);

	}
	// printf("iterator ends at:%d\n",iterator);
	
	printf("\npocet bytu prijatych: %d\n\n",n);
	
	close(sockfd); 
	// */
	return 0;
}
