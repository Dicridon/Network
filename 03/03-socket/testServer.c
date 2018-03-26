#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>

int s;
struct sockaddr_in server;

int result[26] = {0};
int h2[26];
int h3[26];

int novel_size(const char* name) {
    FILE *fd = fopen(name, "r");
    char buffer[1024];
    int block_size = 1024;
    int read_size;
    int word_count = 0;
    while ((read_size = fread(buffer,
			      sizeof(char),
			      block_size, fd)) == block_size) {
	word_count += read_size;
    }
    word_count += read_size;
    fclose(fd);
    return word_count;
}

void* handle(void* in) {
    int c, cs;
    struct sockaddr_in client;

    char* greetH2 = "Hello, 10.0.0.2, this is a reply from server";
    char* greetH3 = "Hello, 10.0.0.3, this is a reply from server";
    
    c = sizeof(struct sockaddr_in);
    if ((cs = accept(s, (struct sockaddr *)&client, (socklen_t *)&c)) < 0) {
        perror("accept failed");
        return NULL;
    }
    printf("Connection accepted\n");

    printf("Client address is %s\n", inet_ntoa(client.sin_addr));

    // Greeting
    if(strcmp(inet_ntoa(client.sin_addr), "10.0.0.2") == 0) {
	write(cs, greetH2, strlen(greetH2));
    } else {
	write(cs, greetH3, strlen(greetH3));
    }

    // Dispatch some work for each worker
    unsigned int mlen = strlen((char*) in);
    printf("Server will send '%d' to clients\n", mlen);
    unsigned int net_mlen = htonl(mlen);
    write(cs, &net_mlen, sizeof(net_mlen));

    // send file name
    printf("Server will send '%s' to clients\n", (char*)in);
    write(cs, (char*)in, mlen);

    // send partition
    int word_count = novel_size((char*)in);
    int start;
    int end;
    if(strcmp(inet_ntoa(client.sin_addr), "10.0.0.2") == 0) {
	start = htonl(0);
	end = htonl(word_count / 2);
	printf("start and end point for 10.0.0.2 is %d and %d\n",
	       ntohl(start), ntohl(end));
	write(cs, &start, sizeof(start));
	write(cs, &end, sizeof(end));
    } else {
	start = htonl(word_count / 2 + 1);
	end = htonl(word_count);
	printf("start and end point for 10.0.0.3 is %d and %d\n",
	       ntohl(start), ntohl(end));
	write(cs, &start, sizeof(start));
	write(cs, &end, sizeof(end));
    }

    // receiving confirmation of start of counting
    char confirm[128];
    if(recv(cs, confirm, 128, 0) < 0){
	printf("Confirmation errore\n");
    } else {
	printf("Confirmation of %s received: %s\n",
	       inet_ntoa(client.sin_addr), confirm);
    }

    
    // receiving counting result
    for(int i = 0; i < 26; i++) {
	if(strcmp(inet_ntoa(client.sin_addr), "10.0.0.2") == 0) {
	    if (recv(cs, h2+i, sizeof(int), 0) < 0) {
		printf("10.0.0.2 failed\n");
		return in;
	    } else {
		h2[i] = ntohl(h2[i]);
	    }
	} else {
	    if (recv(cs, h3+i, sizeof(int), 0) < 0) {
		printf("10.0.0.3 failed\n");
		return in;
	    } else {
		h3[i] = ntohl(h3[i]);
	    }
	}	
    }

    return in;
}

int main(int argc, char *argv[]) {
    if(argc != 2) {
	printf("You have to input one and only one file name\n");
	return -1;
    }

    // Create socket
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Could not create socket\n");
		return -1;
    }
    printf("Socket created\n");
     
    // Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(8888);
     
    // Bind
    if (bind(s,(struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("bind failed. Error\n");
        return -1;
    }
    printf("bind done\n");
     
    // Listen
    listen(s, 3);
     
    // Accept and incoming connection
    printf("Waiting for incoming connections...\n\n");

    pthread_t p1;
    pthread_t p2;

    pthread_create(&p1, NULL, handle, argv[1]);
    pthread_create(&p2, NULL, handle, argv[1]);

    pthread_join(p1, NULL);
    pthread_join(p2, NULL);

    printf("results from two clients are: \n");
    puts("h2:");
    for(int i = 0; i < 26; i++) {
	printf("%c: %d", 'a'+i, h2[i]);
	if(i % 4 == 0)
	    puts("");
    }

    puts("\nh3:");
    for(int i = 0; i < 26; i++) {
	printf("%c: %d", 'a'+i, h3[i]);
	if(i % 4 == 0)
	    puts("");
    }

    puts("\nFinal results:");
    for(int i = 0; i < 26; i++) {
	printf("%c: %d\n", 'a' + i, h2[i] + h3[i]);
    }
    return 0;
}
