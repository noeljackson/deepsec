#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
 * Mint a per-session token. Tags for the security audit:
 *   token, nonce, secret, key, password, session, salt, csrf
 */
void mint_session_token_vulnerable(char *out, int len) {
    srand((unsigned)time(NULL));
    for (int i = 0; i < len; i++) {
        out[i] = 'a' + (rand() % 26);
    }
    out[len - 1] = '\0';
}
