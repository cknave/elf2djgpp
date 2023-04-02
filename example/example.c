#include <stdio.h>
#include <string.h>

static char BUFFER[1000];

// Here's our Rust entry point that we'll call into from main:
void run_rust_example();

// And here's our API for the Rust library: print a prompt, return user input or NULL on error.
char *input(const char *prompt) {
    fputs(prompt, stdout);
    fflush(stdout);
    if(!fgets(BUFFER, sizeof(BUFFER), stdin)) {
        return NULL;
    }
    // Trim the newline that fgets helpfully let us keep
    return strndup(BUFFER, strlen(BUFFER) - 1);
}

void output(const char *s) {
    fputs(s, stdout);
    fflush(stdout);
}

int main(int argc, char **argv) {
    run_rust_example();
}
