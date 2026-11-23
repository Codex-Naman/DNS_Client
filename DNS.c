
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SIZE 512

#pragma pack(push,1)
typedef struct {
    uint16_t id, flags, qdcount, ancount, nscount, arcount;
} DNSHeader;
#pragma pack(pop)

// Convert record string to DNS QTYPE
int get_qtype(char *s) {
    if (!strcmp(s,"A")) return 1;
    if (!strcmp(s,"NS")) return 2;
    if (!strcmp(s,"SOA")) return 6;
    if (!strcmp(s,"MX")) return 15;
    if (!strcmp(s,"AAAA")) return 28;
    return 0;
}

// Encode domain name
int encode_domain(unsigned char *b, char *domain) {
    char copy[256];
    snprintf(copy,sizeof(copy),"%s",domain);
    int p=0;
    char *token=strtok(copy,".");

    while(token) {
        int n=strlen(token);
        if(!n || n>63 || p+n+2>255) return -1;
        b[p++]=n;
        memcpy(b+p,token,n);
        p+=n;
        token=strtok(NULL,".");
    }
    b[p++]=0;
    return p;
}

// Decode DNS compressed domain name
int decode_domain(unsigned char *b,int size,int *offset,char *out) {
    int p=*offset,jump=0,used=0,jumps=0,o=0;

    while(p<size) {
        int n=b[p++];

        if((n&0xC0)==0xC0) {
            if(p>=size || ++jumps>32) return -1;
            int ptr=((n&0x3F)<<8)|b[p++];
            if(ptr>=size) return -1;
            if(!jump) used+=2;
            jump=1;
            p=ptr;
            continue;
        }

        if(n&0xC0) return -1;
        if(!jump) used++;
        if(!n) break;

        if(p+n>size || o+n+1>=256) return -1;
        if(o) out[o++]='.';
        memcpy(out+o,b+p,n);
        o+=n;
        p+=n;
        if(!jump) used+=n;
    }

    out[o]=0;
    *offset+=used;
    return 0;
}

int main() {
    unsigned char b[SIZE]={0};
    char domain[256],type[10],name[256],value[256];
    int qtype,sock;

    printf("\n========== DNS CLIENT ==========\n");
    printf("Enter domain: ");
    if(scanf("%255s",domain)!=1) return 1;

    printf("\nRecord Types: A | AAAA | NS | MX | SOA\n");
    printf("Enter record type: ");
    if(scanf("%9s",type)!=1) return 1;

    for(int i=0;type[i];i++)
        if(type[i]>='a' && type[i]<='z') type[i]-=32;

    qtype=get_qtype(type);
    if(!qtype) {
        printf("Invalid record type!\n");
        return 1;
    }

    // Create UDP socket
    sock=socket(AF_INET,SOCK_DGRAM,0);
    if(sock<0) { perror("Socket"); return 1; }

    // Set receive timeout
    struct timeval timeout={3,0};
    setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));

    struct sockaddr_in server={0};
    server.sin_family=AF_INET;
    server.sin_port=htons(53);
    inet_pton(AF_INET,"8.8.8.8",&server.sin_addr);

    // Construct DNS query
    DNSHeader h={0};
    h.id=htons(1234);
    h.flags=htons(0x0100);
    h.qdcount=htons(1);
    memcpy(b,&h,sizeof(h));

    int p=sizeof(h),n=encode_domain(b+p,domain);
    if(n<0) { printf("Invalid domain!\n"); close(sock); return 1; }
    p+=n;

    uint16_t t=htons(qtype),c=htons(1);
    memcpy(b+p,&t,2); p+=2;
    memcpy(b+p,&c,2); p+=2;

    // Send DNS request
    if(sendto(sock,b,p,0,(struct sockaddr*)&server,sizeof(server))!=p) {
        perror("Send failed"); close(sock); return 1;
    }

    // Receive DNS response
    socklen_t sl=sizeof(server);
    int r=recvfrom(sock,b,sizeof(b),0,(struct sockaddr*)&server,&sl);
    close(sock);

    if(r<0) { perror("Receive failed"); return 1; }

    memcpy(&h,b,sizeof(h));
    uint16_t flags=ntohs(h.flags);

    if(ntohs(h.id)!=1234 || !(flags&0x8000)) {
        printf("Invalid DNS response!\n");
        return 1;
    }

    printf("\n========== DNS RESPONSE ==========\n");
    printf("Domain  : %s\nType    : %s\n",domain,type);
    printf("Status  : ");

    switch(flags&15) {
        case 0: printf("NOERROR\n"); break;
        case 1: printf("FORMERR\n"); break;
        case 2: printf("SERVFAIL\n"); break;
        case 3: printf("NXDOMAIN\n"); break;
        case 4: printf("NOTIMP\n"); break;
        case 5: printf("REFUSED\n"); break;
        default: printf("UNKNOWN\n");
    }

    printf("Answers : %u\n",ntohs(h.ancount));

    // Skip DNS questions
    p=sizeof(h);
    for(int i=0;i<ntohs(h.qdcount);i++) {
        if(decode_domain(b,r,&p,name)<0 || p+4>r) {
            printf("Invalid question section\n"); return 1;
        }
        p+=4;
    }

    // Parse DNS answer records
    for(int i=0;i<ntohs(h.ancount);i++) {
        if(decode_domain(b,r,&p,name)<0 || p+10>r) break;

        uint16_t rt,cl,rd;
        uint32_t ttl;

        memcpy(&rt,b+p,2); p+=2;
        memcpy(&cl,b+p,2); p+=2;
        memcpy(&ttl,b+p,4); p+=4;
        memcpy(&rd,b+p,2); p+=2;

        rt=ntohs(rt); cl=ntohs(cl);
        ttl=ntohl(ttl); rd=ntohs(rd);

        if(p+rd>r) break;
        int end=p+rd;

        if(cl==1) {
            printf("\nRecord Name : %s\nTTL         : %u seconds\n",name,ttl);

            if(rt==1 && rd==4) {
                inet_ntop(AF_INET,b+p,value,sizeof(value));
                printf("Type        : A (IPv4)\nAddress     : %s\n",value);
            }

            else if(rt==28 && rd==16) {
                inet_ntop(AF_INET6,b+p,value,sizeof(value));
                printf("Type        : AAAA (IPv6)\nAddress     : %s\n",value);
            }

            else if(rt==2) {
                int x=p;
                if(decode_domain(b,r,&x,value)==0 && x==end)
                    printf("Type        : NS\nName Server : %s\n",value);
            }

            else if(rt==15 && rd>=3) {
                uint16_t priority;
                memcpy(&priority,b+p,2);
                int x=p+2;
                if(decode_domain(b,r,&x,value)==0 && x==end)
                    printf("Type        : MX\nPriority    : %u\nMail Server : %s\n",
                           ntohs(priority),value);
            }

            else if(rt==6) {
                int x=p;
                char primary[256],admin[256];

                if(decode_domain(b,r,&x,primary)==0 &&
                   decode_domain(b,r,&x,admin)==0 && x+20==end) {
                    uint32_t v[5];
                    for(int j=0;j<5;j++) {
                        memcpy(&v[j],b+x+j*4,4);
                        v[j]=ntohl(v[j]);
                    }
                    printf("Type        : SOA\nPrimary NS  : %s\nAdmin       : %s\n"
                           "Serial      : %u\nRefresh     : %u\nRetry       : %u\n"
                           "Expire      : %u\nMinimum TTL : %u\n",
                           primary,admin,v[0],v[1],v[2],v[3],v[4]);
                }
            }
        }
        p=end;
    }

    printf("\n==================================\n");
    return 0;
}
