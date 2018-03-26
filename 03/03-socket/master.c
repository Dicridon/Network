#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>

int s;
struct sockaddr_in server;

char ip2[16];
char ip3[16];

int h2[26];
int h3[26];
int result[26] = {0};

int setup_server_helper() {
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
    return 0;
}

int setup_server() {
    setup_server_helper();
    
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
    return 0;
}

int novel_size(const char* name) {
    FILE *fd = fopen(name, "r");
    if(fd == NULL)
	return 0;
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

int get_conf(char *in) {
    FILE *fp = fopen("workers.conf", "rb");
    if(fp == NULL) {
	printf("File %s not found\n", in);
	return -1;
    }
    fscanf(fp, "%s", ip2);
    fscanf(fp, "%s", ip3);

    puts("Workers conf: ");
    puts(ip2);
    puts(ip3);
    return 0;
}

void dispatch_partition(int cs, struct sockaddr_in *client, char* in){
    int word_count = novel_size(in);
    int start;
    int end;
    if(strcmp(inet_ntoa(client->sin_addr), ip2) == 0) {
	start = htonl(0);
	end = htonl(word_count / 2);
	printf("start and end point for %s is %d and %d\n",
	       ip2, ntohl(start), ntohl(end));
	write(cs, &start, sizeof(start));
	write(cs, &end, sizeof(end));
    } else {
	start = htonl(word_count / 2 + 1);
	end = htonl(word_count);
	printf("start and end point for %s is %d and %d\n",
	       ip3, ntohl(start), ntohl(end));
	write(cs, &start, sizeof(start));
	write(cs, &end, sizeof(end));
    }    
}

void dispatch(int cs, struct sockaddr_in *client, char *in) {
    // Dispatch some work for each worker
    unsigned int mlen = strlen((char*) in);
    printf("Server will send '%d' to clients\n", mlen);
    unsigned int net_mlen = htonl(mlen);
    write(cs, &net_mlen, sizeof(net_mlen));

    // send file name
    printf("Server will send '%s' to clients\n", (char*)in);
    write(cs, (char*)in, mlen);

    // send partition
    dispatch_partition(cs, client, in);
}

int confirm(int cs, struct sockaddr_in *client) {
    char conf[128];
    if(recv(cs, conf, 128, 0) < 0){
	printf("Confirmation errore\n");
	return -1;
    } else {
	printf("Confirmation of %s received: %s\n",
	       inet_ntoa(client->sin_addr), conf);
    }
    return 0;
}

int receive(int cs, struct sockaddr_in *client) {
    if(strcmp(inet_ntoa(client->sin_addr), ip2) == 0) {
	for(int i = 0; i < 26; i++) {
	    if (recv(cs, h2+i, sizeof(int), 0) < 0) {
		printf("%s failed\n", ip2);
		return -1;
	    } else {
		h2[i] = ntohl(h2[i]);
	    }
	}
    } else {
	for(int i = 0; i < 26; i++) {
	    if (recv(cs, h3+i, sizeof(int), 0) < 0) {
		printf("%s failed\n", ip3);
		return -1;
	    } else {
		h3[i] = ntohl(h3[i]);
	    }
	}
    }
    return 0;
}

int accept_and_check(int *cs, struct sockaddr_in *client) {
    int c;
    char* greet = "Hello, this is a reply from server";         
    c = sizeof(struct sockaddr_in);                             
    *cs = accept(s, (struct sockaddr *)client, (socklen_t *)&c);
    if (*cs < 0) { 
        perror("accept failed");
        return -1;
    }
    printf("Connection accepted\n");

    printf("Client address is %s\n", inet_ntoa(client->sin_addr));
    // Greeting
    write(*cs, greet, strlen(greet));
    
    return 0;
}

void* handle(void* in) {
    int cs;
    struct sockaddr_in client;

    accept_and_check(&cs, &client);

    // dispatch some work
    puts("dispatching...");
    dispatch(cs, &client, (char *)in);

    puts("comfirming...");
    // receiving confirmation of start of counting
    if(confirm(cs, &client))
	return NULL;

    puts("receiving...");
    // receiving counting result
    if(receive(cs, &client) != 0)
	return NULL;
    return in;
}

int main_work(char *in) {
    pthread_t p1;
    pthread_t p2;
    void *status = NULL;
    pthread_create(&p1, NULL, handle, in);
    pthread_create(&p2, NULL, handle, in);

    pthread_join(p1, &status);
    pthread_join(p2, &status);
    
    if(status == NULL)
	return -1;
    return 0;
}

void show_results() {
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
}

int main(int argc, char *argv[]) {
    if(argc != 2) {
	printf("You have to input one and only one file name\n");
	return -1;
    }

    if(get_conf(argv[1]) != 0) {
	return -1;
    }

    // setup a server
    if(setup_server() != 0) {
	printf("Server setup failed\n");
	return -1;
    }
     
    // main work
    if(main_work(argv[1]) != 0)
	return -1;

    show_results();
    return 0;
}
