#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8888

void print_ASCII(const char* to_print)
{
	printf("ASCII values for the entered command:\n");
	for (int i = 0; i <= strlen(to_print); ++i) {
		printf("%c: %d\n", to_print[i], to_print[i]);
	}
}

SSL_CTX* create_client_context() {
    SSL_CTX* ctx;

    // Initialize the SSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create a new SSL context for the client
    ctx = SSL_CTX_new(TLS_client_method());
	
	// Error checking mechanism
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set supported SSL/TLS versions (optional but recommended)
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    return ctx;
}

void send_command(SSL* ssl, const char* command) {
    SSL_write(ssl, command, (strlen(command) + 1));
}


void receive_response(SSL* ssl) {
    char response[1024];
    size_t total_received = 0;
    ssize_t received;

    // Receive until there is no more data
    while ((received = SSL_read(ssl, response + total_received, sizeof(response) - total_received - 1)) > 0) {
        total_received += received;
    }

    // Null-terminate the received data
    response[total_received] = '\0';

    // Check if the received data is "null"
    if (strcmp(response, "null") == 0) {
        printf("Received null response\n");
        return;
    }

    // Check if the received data is a JSON object
    if (strstr(response, "{") != NULL) {
        // It's a JSON object, parse it and display
        struct json_object* received_obj = json_tokener_parse(response);
        const char* pretty_json_str = json_object_to_json_string_ext(received_obj, JSON_C_TO_STRING_PRETTY);
        printf("Received JSON object:\n%s\n", pretty_json_str);
        json_object_put(received_obj);  // Release the parsed JSON object
    } else {
        // It's a regular string, print it
        printf("Server Response:\n%s\n", response);
    }
}

void remove_newline(char *str) {
    size_t length = strlen(str);
    if (length > 0 && str[length - 1] == '\n') {
        str[length - 1] = '\0';
    }
}

void run_client(SSL_CTX* ctx) {
    int client_fd;
    struct sockaddr_in server_addr;

    // Create a socket
    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Initialize server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(PORT);

    // Connect to the server
    if (connect(client_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    // Set up the SSL connection
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        char command[256];

        // Get command input from the user
        printf("Enter command: ");
        fgets(command, sizeof(command), stdin);

		//print_ASCII(command);

        remove_newline(command);
		
        // Send the command to the server
        send_command(ssl, command);

        // Receive and display the server's response
        receive_response(ssl);

        // Clean up
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    close(client_fd);
}

int main() {
    SSL_CTX* ctx = create_client_context();
    run_client(ctx);

    // Clean up the SSL library
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
