#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8888

json_object* objA;
json_object* objB;
json_object* objC;
json_object* objD;

SSL_CTX* create_server_context() {
    SSL_CTX* ctx;

    // Initialize the SSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_server_method());

    // Load server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "/home/Administrator/CN Project/server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "/home/Administrator/CN Project/server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void create_json_objects() {
    objA = json_object_new_object();
    json_object_object_add(objA, "name", json_object_new_string("Object1"));
    json_object_object_add(objA, "data", json_object_new_string("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse potenti. Proin eget interdum odio. Vestibulum nec urna vel quam pharetra posuere. Nullam in elit ut ligula finibus tristique."));

    objB = json_object_new_object();
    json_object_object_add(objB, "name", json_object_new_string("Object2"));
    json_object_object_add(objB, "data", json_object_new_int(1234567890));

    objC = json_object_new_object();
    json_object_object_add(objC, "name", json_object_new_string("Object3"));
    json_object_object_add(objC, "data", json_object_new_double(3.141592653589793));

    objD = json_object_new_object();
    json_object_object_add(objD, "name", json_object_new_string("Object4"));
    json_object_object_add(objD, "data", json_object_new_array());

    // Add a large array of integers to obj4
    for (int i = 0; i < 1000; ++i) {
        json_object_array_add(json_object_object_get(objD, "data"), json_object_new_int(i));
    }
}

void send_json_object(SSL* ssl, const char* json_object_name) {
    json_object* requested_obj = NULL;

    // Determine which JSON object to send based on the requested name
    if (strcmp(json_object_name, "objA") == 0) {
        requested_obj = objA;
    } else if (strcmp(json_object_name, "objB") == 0) {
        requested_obj = objB;
    } else if (strcmp(json_object_name, "objC") == 0) {
        requested_obj = objC;
    } else if (strcmp(json_object_name, "objD") == 0) {
        requested_obj = objD;
    } else {
        SSL_write(ssl, "Invalid JSON object name", strlen("Invalid JSON object name"));
        return;
    }

    // Convert the requested JSON object to a string
    const char* json_str = json_object_to_json_string_ext(requested_obj, JSON_C_TO_STRING_PRETTY);

    // Send the JSON string to the client
    SSL_write(ssl, json_str, strlen(json_str));
}


void handle_command(SSL* ssl, char* command) {
    char response[256];

    // Print the received command
    printf("Received command: %s\n", command);

    if (strcmp(command, "echo") == 0) {
        SSL_write(ssl, "Enter message to echo: ", strlen("Enter message to echo: "));
        SSL_read(ssl, response, sizeof(response));
        SSL_write(ssl, response, strlen(response));
    } else if (strcmp(command, "ls") == 0) {
        FILE* ls_output = popen("ls", "r");
        fread(response, 1, sizeof(response), ls_output);
        SSL_write(ssl, response, strlen(response));
        pclose(ls_output);
    } else if (strcmp(command, "pwd") == 0) {
        FILE* pwd_output = popen("pwd", "r");
        fread(response, 1, sizeof(response), pwd_output);
        SSL_write(ssl, response, strlen(response));
        pclose(pwd_output);
    } else if (strcmp(command, "whoami") == 0) {
        FILE* whoami_output = popen("whoami", "r");
        fread(response, 1, sizeof(response), whoami_output);
        SSL_write(ssl, response, strlen(response));
        pclose(whoami_output);
    } else if (strcmp(command, "date") == 0) {
        FILE* date_output = popen("date", "r");
        fread(response, 1, sizeof(response), date_output);
        SSL_write(ssl, response, strlen(response));
        pclose(date_output);
    } else if (strncmp(command, "GET ", 4) == 0) {
        // Extract the JSON object name from the command
        const char* json_object_name = command + 4;

        // Send the requested JSON object to the client
        send_json_object(ssl, json_object_name);
    } else {
        SSL_write(ssl, "Invalid command", strlen("Invalid command"));
    }

    // Clear the command buffer
    memset(command, 0, sizeof(command));
}



void run_server(SSL_CTX* ctx) {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    // Create a socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Initialize server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind the socket
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Binding failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 10) == -1) {
        perror("Listening failed");
        exit(EXIT_FAILURE);
    }

    while (1) {
        // Accept a connection inside the loop
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd == -1) {
            perror("Acceptance failed");
            exit(EXIT_FAILURE);
        }

        // Set up the SSL connection
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            char command[256];

            // Receive command from the client
            SSL_read(ssl, command, sizeof(command));

            // Print the received command (added for debugging)
            printf("Received command: %s\n", command);

            // Handle the received command
            handle_command(ssl, command);

            // Clean up
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }

        // Close the accepted socket inside the loop
        close(client_fd);
    }

    close(server_fd);
}



int main() {
    SSL_CTX* ctx = create_server_context();
    run_server(ctx);

    // Clean up the SSL library
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
