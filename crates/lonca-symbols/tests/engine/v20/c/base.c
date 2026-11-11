#include <stdio.h>

#define LIMIT 10

/* The total. */
static int total = 0;

struct point {
    int x;
    int y;
};

typedef struct node {
    struct node *next;
} node;

enum color { RED, BLUE };

int add(int a, int b) {
    return a + b;
}

static char *name(void) {
    return "x";
}

#ifdef DEBUG
int debug(void) {
    return 1;
}
#endif
