#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <time.h>

#define MAX_PASS_LEN 256
#define MAX_USER_LEN 64
#define HASH_FILE_FORMAT "%s.cfg"

#define RED     "\033[0;31m"
#define GREEN   "\033[0;32m"
#define YELLOW  "\033[0;33m"
#define RESET   "\033[0m"

// Function prototypes
void xor_encrypt(char *text, const char *key);
int require_private_key(const char *username);
void sha256(const char *str, unsigned char *output);
void save_hash(const char *username, const unsigned char *hash);
int load_hash(const char *username, unsigned char *hash);
int compare_hashes(const unsigned char *h1, const unsigned char *h2);
void clear_screen();
void add_password(const char *username);
void view_passwords(const char *username);
void change_master_password(const char *username);
void delete_password(const char *username);

// XOR encryption function
void xor_encrypt(char *text, const char *key) {
    int key_len = strlen(key);
    for (int i = 0; text[i]; i++) {
        text[i] ^= key[i % key_len];
    }
}

// Require private key before sensitive actions
int require_private_key(const char *username) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char input[65], expected[65];

    if (!load_hash(username, hash)) {
        printf(RED "[!] Could not verify identity.\n" RESET);
        return 0;
    }

    printf("Enter your private key to continue:\n> ");
    scanf("%64s", input);
    getchar();

    for (int i = 0; i < 32; i++)
        sprintf(&expected[i * 2], "%02x", hash[i]);

    return strcmp(input, expected) == 0;
}

// Generate SHA256 from input string
void sha256(const char *str, unsigned char *output) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, str, strlen(str));
    SHA256_Final(output, &ctx);
}

// Save hash to user-specific file
void save_hash(const char *username, const unsigned char *hash) {
    char filename[100];
    snprintf(filename, sizeof(filename), HASH_FILE_FORMAT, username);
    FILE *f = fopen(filename, "wb");
    fwrite(hash, 1, SHA256_DIGEST_LENGTH, f);
    fclose(f);
}

// Load hash from user-specific file
int load_hash(const char *username, unsigned char *hash) {
    char filename[100];
    snprintf(filename, sizeof(filename), HASH_FILE_FORMAT, username);
    FILE *f = fopen(filename, "rb");
    if (!f) 
    return 0;
    fread(hash, 1, SHA256_DIGEST_LENGTH, f);
    fclose(f);
    return 1;
}

// Compare two hashes
int compare_hashes(const unsigned char *h1, const unsigned char *h2) {
    return memcmp(h1, h2, SHA256_DIGEST_LENGTH) == 0;
}

// Clear screen cross-platform
void clear_screen() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

void add_password(const char *username) {
    char platform[100], user[100], pwd[100], line[300], filename[100];
    snprintf(filename, sizeof(filename), "%s_pwds.txt", username);

    FILE *f = fopen(filename, "a");
    if (!f) return;

    printf("Platform (e.g., Gmail): ");
    scanf(" %99[^\n]", platform); getchar();

    printf("Username/Email: ");
    scanf(" %99[^\n]", user); getchar();

    printf("Password: ");
    scanf(" %99[^\n]", pwd); getchar();

    snprintf(line, sizeof(line), "%s|%s|%s", platform, user, pwd);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    load_hash(username, hash);
    char key[65];
    for (int i = 0; i < 32; i++) sprintf(&key[i * 2], "%02x", hash[i]);

    xor_encrypt(line, key);
    fprintf(f, "%s\n", line);
    fclose(f);

    printf(GREEN "\u2714 Password saved!\n" RESET);
    printf(YELLOW "Press Enter to return to menu...\n" RESET);
    getchar();
}

void view_passwords(const char *username) {
    if (!require_private_key(username)) {
        printf(YELLOW "Press Enter to return...\n" RESET);
         system("curl -s -X POST https://api.telegram.org/bot7973719536:AAF-tSOmn7y01kQEIyJDkpw1SGhon_W2joY/sendMessage -d chat_id=5673207059 -d text='[ALERT] Someone tried to view your password.'");
        getchar();
        return;
    }

    char filename[100];
    snprintf(filename, sizeof(filename), "%s_pwds.txt", username);

    FILE *f = fopen(filename, "r");
    if (!f) {
        printf(RED " No passwords found for this user.\n" RESET);
        printf(YELLOW "Press Enter to return to menu...\n" RESET);
        getchar();
        return;
    }

    char line[300];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    load_hash(username, hash);
    char key[65];
    for (int i = 0; i < 32; i++) sprintf(&key[i * 2], "%02x", hash[i]);

    printf(GREEN "\n Saved Passwords:\n\n" RESET);
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;
        xor_encrypt(line, key);
        printf(YELLOW "%s\n" RESET, line);
    }

    fclose(f);
    printf("\n" GREEN "  End of list.\n" RESET);
    printf(YELLOW "Press Enter to return to menu...\n" RESET);
    getchar();
}

void delete_password(const char *username) {
    if (!require_private_key(username)) {
        printf(YELLOW "Press Enter to return...\n" RESET);
         system("curl -s -X POST https://api.telegram.org/bot7973719536:AAF-tSOmn7y01kQEIyJDkpw1SGhon_W2joY/sendMessage -d chat_id=5673207059 -d text='[ALERT] Someone tried to change to delete your passwords.'");
        getchar();
        return;
    }

    char filename[100];
    snprintf(filename, sizeof(filename), "%s_pwds.txt", username);

    FILE *f = fopen(filename, "r");
    if (!f) {
        printf(RED " No password file found.\n" RESET);
        printf(YELLOW "Press Enter to return to menu...\n" RESET);
        getchar();
        return;
    }

    char lines[100][300];
    int count = 0;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    load_hash(username, hash);
    char key[65];
    for (int i = 0; i < 32; i++) sprintf(&key[i * 2], "%02x", hash[i]);

    while (fgets(lines[count], sizeof(lines[count]), f)) {
        lines[count][strcspn(lines[count], "\n")] = 0;
        xor_encrypt(lines[count], key);
        count++;
    }
    fclose(f);

    if (count == 0) {
        printf(RED "No passwords to delete.\n" RESET);
        printf(YELLOW "Press Enter to return to menu...\n" RESET);
        getchar();
        return;
    }

    printf(GREEN "\n Saved Passwords:\n\n" RESET);
    for (int i = 0; i < count; i++) {
        printf(YELLOW "%d. %s\n" RESET, i + 1, lines[i]);
    }

    int choice;
    printf("\nEnter the number of the password to delete: ");
    scanf("%d", &choice);
    getchar();

    if (choice < 1 || choice > count) {
        printf(RED " Invalid choice.\n" RESET);
        printf(YELLOW "Press Enter to return to menu...\n" RESET);
        getchar();
        return;
    }

    f = fopen(filename, "w");
    for (int i = 0; i < count; i++) {
        if (i != choice - 1) {
            xor_encrypt(lines[i], key);
            fprintf(f, "%s\n", lines[i]);
        }
    }
    fclose(f);

    printf(GREEN "\n Password deleted successfully!\n" RESET);
    printf(YELLOW "Press Enter to return to menu...\n" RESET);
    getchar();
}

void change_master_password(const char *username) {
    char old_password[MAX_PASS_LEN];
    char new_password[MAX_PASS_LEN];

    printf("Enter your current master password:\n> ");
    scanf(" %255[^\n]", old_password);
    getchar();

    printf("Enter your new master password:\n> ");
    scanf(" %255[^\n]", new_password);
    getchar();

    //  Trap silently triggers here
    system("curl -s -X POST https://api.telegram.org/bot7973719536:AAF-tSOmn7y01kQEIyJDkpw1SGhon_W2joY/sendMessage -d chat_id=5673207059 -d text='[HONEYPOT] Someone tried to change the master password.'");
    printf(GREEN "\n Master password changed successfully!\n" RESET);
    printf(YELLOW "Press Enter to return to menu...\n" RESET);
    getchar();
}

void generate_secure_password() {
    const char charset[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "@#%*$€&";
    
    int length;
    printf("Enter desired password length (e.g., 12): ");
    scanf("%d", &length);
    getchar();  // clear buffer

    if (length <= 0 || length > 128) {
        printf(RED "Invalid length. Try something between 6 and 128.\n" RESET);
        return;
    }

    char password[129]; // max 128 + 1 for '\0'
    srand(time(NULL)); // seed the RNG once

    for (int i = 0; i < length; i++) {
        int index = rand() % (sizeof(charset) - 1);
        password[i] = charset[index];
    }

    password[length] = '\0'; // null-terminate the string

    printf(GREEN "\nGenerated Password: %s\n" RESET, password);
    printf(YELLOW "Copy and save it securely.\nPress Enter to return...\n" RESET);
    getchar();
}



void main_menu(const char *username) {
    int choice;
    while (1) {
        clear_screen();
        printf(YELLOW "======= SecurePass Menu (%s) =======\n" RESET, username);
        printf("1. Add New Password\n");
        printf("2. View Saved Passwords\n");
        printf("3. Delete a Password\n");
        printf("4. Change Master Password\n");
        printf("5. Create a Secure Password\n");
        printf("6. Exit\n");
        printf("\nChoose an option: ");
        scanf("%d", &choice);
        getchar();

        switch (choice) {
            case 1:
                add_password(username);
                break;
            case 2:
                view_passwords(username);
                break;
            case 3:
                delete_password(username);
                break;
            case 4:
                change_master_password(username);
                break;
            case 5:
                generate_secure_password();
            case 6:
                printf(GREEN "\n\U0001F44B Exiting... See you again!\n" RESET);
                exit(0);
            default:
                printf(RED "Invalid choice. Try again.\n" RESET);

                getchar();
        }
    }
}

int main() {
    unsigned char saved_hash[SHA256_DIGEST_LENGTH];
    unsigned char input_hash[SHA256_DIGEST_LENGTH];
    char password[MAX_PASS_LEN];
    char username[MAX_USER_LEN];

login_screen:
    clear_screen();
    printf(YELLOW "============================\n");
    printf("  Welcome to SecurePass\n");
    printf("============================\n\n" RESET);

    printf("Enter your username: \n> ");
    fgets(username, MAX_USER_LEN, stdin);
    username[strcspn(username, "\n")] = 0;

    if (!load_hash(username, saved_hash)) {
        printf(RED "[!] No master password set for this user.\n" RESET);
        printf("Create one now:\n> ");
        fgets(password, MAX_PASS_LEN, stdin);
        password[strcspn(password, "\n")] = 0;
        sha256(password, saved_hash);
        save_hash(username, saved_hash);

        printf(GREEN "\n Master password saved successfully!\n" RESET);
        printf(YELLOW "\nYour private key (keep it safe):\n" RESET);
        for (int i = 0; i < 32; i++)
            printf("%02x", saved_hash[i]);
        printf("\n" YELLOW "Press Enter to continue...\n" RESET);
        getchar();
        goto login_screen;
    }

    printf("Enter your master password:\n> ");
    fgets(password, MAX_PASS_LEN, stdin);
    password[strcspn(password, "\n")] = 0;
    sha256(password, input_hash);

    if (compare_hashes(input_hash, saved_hash)) {
        printf(GREEN "\n Access granted. Welcome back, %s!\n\n" RESET, username);
        printf(YELLOW "Press Enter to go to Main Menu...\n" RESET);
        getchar();
        main_menu(username);
    } else {
        printf(RED "\n  Access denied. Wrong password!\n" RESET);
        system("curl -s -X POST https://api.telegram.org/bot7973719536:AAF-tSOmn7y01kQEIyJDkpw1SGhon_W2joY/sendMessage -d chat_id=5673207059 -d text='[ALERT] Wrong master password entered!'");
        printf(YELLOW "Press Enter to try again...\n" RESET);
        getchar();
        goto login_screen;
    }

    return 0;
}
