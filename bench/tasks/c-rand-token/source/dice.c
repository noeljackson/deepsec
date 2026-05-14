#include <stdlib.h>

/* Dice rolls for the game module. No security keywords here. */
int dice_roll(void) {
    return rand() % 6 + 1;
}
