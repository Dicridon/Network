#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

int count_array[26] = {0};

int count_alpha(const char* filename, int start, int end) {
    FILE* fp = fopen(filename, "rb");
    if(!fp)
	return 0;
    int filesz = end - start + 1;
    char *buffer = (char*)malloc(filesz * sizeof(char));
    fseek(fp, start, SEEK_SET);
    fread(buffer, sizeof(char), filesz, fp);
    
    char c;
    for(int i = 0; i < filesz; i++) {
	if(isalpha((c = tolower(buffer[i])))){
	    count_array[c - 'a'] += 1;
	}
    }
    return 0;
}
 
int main(int argc, char *argv[])
{
    int sock;
    struct sockaddr_in server;
    char server_reply[128] = "";
    char filename[128] = "";
     
    //Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        printf("Could not create socket\n");
    }
    printf("Socket created\n");
     
    server.sin_addr.s_addr = inet_addr("10.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons( 8888 );
 
    //Connect to remote server
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("connect failed. Error\n");
        return 1;
    }
     
    printf("Connected\n");

    // connection check
    if (recv(sock, server_reply, 128, 0) < 0) {
	printf("Client recv connection check failed\n");
    } else {
	printf("Server's reply: %s\n", server_reply);
    }

    // work dispatch
    int work_size;
    if (recv(sock, &work_size, sizeof(work_size), 0) < 0) {
	printf("Client recv work size failed\n");
    } else {
	printf("Message length is: %d\n", ntohl(work_size));
    }

    // file name
    work_size = ntohl(work_size);
    if (recv(sock, filename, work_size, 0) < 0) {
	printf("Client recv filename failed\n");
    } else {
	printf("file path length is %d, file path is %s\n",work_size, filename);
    }


    // partition
    int start = 0, end = 0;
    int sf = recv(sock, &start, sizeof(start), 0);
    int ef = recv(sock, &end, sizeof(start), 0);
    if (sf < 0 || ef < 0){
	printf("Client recv partition failed: sf: %d, ef: %d\n", sf, ef);
    } else {
	start = ntohl(start);
	end = ntohl(end);
	printf("partition is %d and %d\n", start, end);
    }

    char *confirm = "Client is ready\n";
    if(send(sock, confirm, strlen(confirm), 0) < 0) {
	printf("Sending confirmation error\n");
    } else {
	printf("Start counting\n");
    }

    count_alpha(filename, start, end);

    puts("Count result");
    for(int i = 0; i < 26; i++) {
	printf("%c: %d\n", 'a'+i, count_array[i]);
	count_array[i] = htonl(count_array[i]);
    }

    for(int i = 0; i < 26; i++){
	send(sock, count_array+i, sizeof(int), 0);
    }
    close(sock);
    return 0;
}
