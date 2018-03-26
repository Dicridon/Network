/* server application */
 
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
 
int main(int argc, const char *argv[])
{
    int s, cs;
    struct sockaddr_in server, client;
    char msg[2000];
     
    // Create socket
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Could not create socket");
		return -1;
    }
    printf("Socket created");
     
    // Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(8888);
     
    // Bind
    if (bind(s,(struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("bind failed. Error");
        return -1;
    }
    printf("bind done");
     
    // Listen
    listen(s, 3);
     
    // Accept and incoming connection
    printf("Waiting for incoming connections...");
     
    // accept connection from an incoming client
    int c = sizeof(struct sockaddr_in);
    if ((cs = accept(s, (struct sockaddr *)&client, (socklen_t *)&c)) < 0) {
        perror("accept failed");
        return 1;
    }
    printf("Connection accepted");
     
    int msg_len = 0;
    // Receive a message from client
    while ((msg_len = recv(cs, msg, sizeof(msg), 0)) > 0) {
        // Send the message back to client
        write(cs, msg, msg_len);
    }
     
    if (msg_len == 0) {
        printf("Client disconnected");
    }
    else { // msg_len < 0
        perror("recv failed");
		return -1;
    }
     
    return 0;
}
