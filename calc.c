#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC(a, type) (type *) Arena_alloc(a, sizeof(type), _Alignof(type))

typedef struct {
    void *memory;
    int offset;
    int capacity;
} Arena;

static Arena *
Arena_new(int capacity)
{
    assert(capacity >= (int) sizeof(Arena));

    void *memory = malloc(capacity);
    Arena *a = (Arena *) memory;
    if (a != NULL) {
        a->memory = memory;
        a->offset = sizeof(Arena);
        a->capacity = capacity;
    }
    return a;
}

static void
Arena_free(Arena *a)
{
    free(a);
}

static void *
Arena_alloc(Arena *a, int size, int align)
{
    int avail = a->capacity - a->offset;
    int padding = -a->offset & (align - 1);
    if (size > avail - padding)
        return NULL;
    void *p = (unsigned char *) a->memory + a->offset + padding;
    a->offset += padding + size;
    return memset(p, 0, size);
}

typedef enum {
    TK_INT,
    TK_PLUS,
    TK_MINUS,
    TK_STAR,
    TK_SLASH,
    TK_CARET,
    TK_LPAREN,
    TK_RPAREN,
    TK_EOL
} TokenType;

typedef struct {
    TokenType type;
    int val;
} Token;

typedef struct {
    const char *src;
    int len;
    int cur;
    Token tok;  // Current token
} Scanner;

typedef enum {
    ND_INT,
    ND_ADD,
    ND_SUB,
    ND_MUL,
    ND_DIV,
    ND_EXP,
    ND_POS,
    ND_NEG,
} NodeType;

typedef struct Node Node;
struct Node {
    NodeType type;
    Node *left;
    Node *right;
    double val;
};

static bool next_token(Scanner *s);

static void
init_scanner(Scanner *s, const char *src, int len)
{
    s->src = src;
    s->len = len;
    s->cur = 0;
}

static bool
is_at_end(Scanner *s)
{
    return s->cur >= s->len;
}

static char
peek(Scanner *s)
{
    return s->src[s->cur];
}

static char
advance(Scanner *s)
{
    return s->src[s->cur++];
}

static void
skip_whitespace(Scanner *s)
{
    while (!is_at_end(s) && isspace(peek(s)))
        advance(s);
}

static bool
consume_number(Scanner *s)
{
    assert(!is_at_end(s) && isdigit(peek(s)));

    int num = 0;
    do {
        int digit = advance(s) - '0';
        if (num > (INT_MAX - digit) / 10)
            return false;
        num = num * 10 + digit;
    } while (!is_at_end(s) && isdigit(peek(s)));

    s->tok.type = TK_INT;
    s->tok.val = num;
    return true;
}

static bool
consume_operator(Scanner *s)
{
    assert(!is_at_end(s));
    switch (peek(s)) {
    case '+':
        s->tok.type = TK_PLUS;
        break;
    case '-':
        s->tok.type = TK_MINUS;
        break;
    case '*':
        s->tok.type = TK_STAR;
        break;
    case '/':
        s->tok.type = TK_SLASH;
        break;
    case '^':
        s->tok.type = TK_CARET;
        break;
    default:
        return false;
    }

    advance(s);
    return true;
}

static bool
next_token(Scanner *s)
{
    skip_whitespace(s);

    if (is_at_end(s)) {
        s->tok.type = TK_EOL;
        return true;
    }

    if (peek(s) == '(') {
        s->tok.type = TK_LPAREN;
        advance(s);
        return true;
    }

    if (peek(s) == ')') {
        s->tok.type = TK_RPAREN;
        advance(s);
        return true;
    }

    if (isdigit(peek(s)))
        return consume_number(s);

    return consume_operator(s);
}

static void
print_token(FILE *f, Token tok)
{
    switch (tok.type) {
    case TK_INT:
        fprintf(f, "INT(%d)", tok.val);
        break;
    case TK_PLUS:
        fprintf(f, "PLUS");
        break;
    case TK_MINUS:
        fprintf(f, "MINUS");
        break;
    case TK_STAR:
        fprintf(f, "STAR");
        break;
    case TK_SLASH:
        fprintf(f, "SLASH");
        break;
    case TK_CARET:
        fprintf(f, "CARET");
        break;
    case TK_LPAREN:
        fprintf(f, "LPAREN");
        break;
    case TK_RPAREN:
        fprintf(f, "RPAREN");
        break;
    default:
        fprintf(f, "???");
    }
}

static bool
is_binop(Token tok)
{
    switch (tok.type) {
    case TK_PLUS:
    case TK_MINUS:
    case TK_STAR:
    case TK_SLASH:
    case TK_CARET:
        return true;
    default:
        return false;
    }
}

static int
get_prec(Token tok)
{
    assert(is_binop(tok));

    switch (tok.type) {
    case TK_PLUS:
    case TK_MINUS:
        return 1;
    case TK_STAR:
    case TK_SLASH:
        return 2;
    case TK_CARET:
        return 3;
    default:
        return 0;
    }
}

static bool
is_right_assoc(Token tok)
{
    assert(is_binop(tok));
    return tok.type == TK_CARET;
}

static NodeType
get_node_type(Token tok)
{
    switch (tok.type) {
    case TK_PLUS:
        return ND_ADD;
    case TK_MINUS:
        return ND_SUB;
    case TK_STAR:
        return ND_MUL;
    case TK_SLASH:
        return ND_DIV;
    case TK_CARET:
        return ND_EXP;
    default:
        return -1;
    }
}

static Node *parse_expr(Scanner *s, int prec, Arena *a);

static Node *
parse_primary(Scanner *s, Arena *a)
{
    Token cur = s->tok;

    switch (cur.type) {
    case TK_INT: {
        if (!next_token(s))
            return NULL;

        Node *node = ALLOC(a, Node);
        if (node == NULL)
            return NULL;

        node->type = ND_INT;
        node->val = (double) cur.val;
        return node;
    }

    case TK_PLUS:
    case TK_MINUS: {
        if (!next_token(s))
            return NULL;

        // Exponentiation takes precedence over negation
        Node *left = parse_expr(s, 3, a);
        Node *node = ALLOC(a, Node);
        if (left == NULL || node == NULL)
            return NULL;

        if (cur.type == TK_PLUS)
            node->type = ND_POS;
        else
            node->type = ND_NEG;

        node->left = left;
        return node;
    }

    case TK_LPAREN: {
        if (!next_token(s))
            return NULL;

        Node *expr = parse_expr(s, 0, a);
        if (expr == NULL || s->tok.type != TK_RPAREN)
            return NULL;

        if (!next_token(s))
            return NULL;

        return expr;
    }

    default:
        return NULL;
    }
}

static Node *
parse_expr(Scanner *s, int min_prec, Arena *a)
{
    Node *lhs = parse_primary(s, a);
    if (lhs == NULL)
        return NULL;

    while (true) {
        Token op = s->tok;
        // Exit point for the parser (when it encounters TK_EOL)
        if (!is_binop(op))
            break;

        int op_prec = get_prec(op);
        if (op_prec < min_prec)
            break;

        int new_prec = is_right_assoc(op) ? op_prec : op_prec + 1;

        if (!next_token(s))
            return NULL;

        Node *rhs = parse_expr(s, new_prec, a);
        if (rhs == NULL)
            return NULL;

        Node *op_node = ALLOC(a, Node);
        if (op_node == NULL)
            return NULL;

        op_node->type = get_node_type(op);
        op_node->left = lhs;
        op_node->right = rhs;
        lhs = op_node;
    }

    return lhs;
}

static Node *
parse(const char *src, int len, Arena *a)
{
    Scanner s;
    init_scanner(&s, src, len);

    if (!next_token(&s))
        return NULL;

    return parse_expr(&s, 0, a);
}

static double
eval(Node *node)
{
    switch (node->type) {
    case ND_INT:
        return node->val;
    case ND_ADD:
        return eval(node->left) + eval(node->right);
    case ND_SUB:
        return eval(node->left) - eval(node->right);
    case ND_MUL:
        return eval(node->left) * eval(node->right);
    case ND_DIV:
        return eval(node->left) / eval(node->right);
    case ND_EXP:
        return pow(eval(node->left), eval(node->right));
    case ND_POS:
        return +eval(node->left);
    case ND_NEG:
        return -eval(node->left);
    default:
        return -1;  // Unreachable
    }
}

static void
print_subtree(FILE *f, Node *root)
{
    switch (root->type) {
    case ND_INT:
        fprintf(f, "%d", (int) root->val);
        break;

    case ND_ADD:
        fprintf(f, "(");
        print_subtree(f, root->left);
        fprintf(f, " + ");
        print_subtree(f, root->right);
        fprintf(f, ")");
        break;

    case ND_SUB:
        fprintf(f, "(");
        print_subtree(f, root->left);
        fprintf(f, " - ");
        print_subtree(f, root->right);
        fprintf(f, ")");
        break;

    case ND_MUL:
        fprintf(f, "(");
        print_subtree(f, root->left);
        fprintf(f, " * ");
        print_subtree(f, root->right);
        fprintf(f, ")");
        break;

    case ND_DIV:
        fprintf(f, "(");
        print_subtree(f, root->left);
        fprintf(f, " / ");
        print_subtree(f, root->right);
        fprintf(f, ")");
        break;

    case ND_EXP:
        fprintf(f, "(");
        print_subtree(f, root->left);
        fprintf(f, " ^ ");
        print_subtree(f, root->right);
        fprintf(f, ")");
        break;

    case ND_POS:
        fprintf(f, "+");
        print_subtree(f, root->left);
        break;

    case ND_NEG:
        fprintf(f, "-");
        print_subtree(f, root->left);
        break;
    }
}

static void
print_tree(FILE *f, Node *root)
{
    print_subtree(f, root);
    fflush(f);
}

#ifdef DEBUG
int
main(void)
{
    const char *src = "-2 ^ 2";

    Arena *a = Arena_new(2048);
    if (a == NULL) {
        printf("Failed to allocate arena\n");
        return 1;
    }

    Node *root = parse(src, strlen(src), a);
    if (root == NULL) {
        printf("Parsing failed\n");
        Arena_free(a);
        return 1;
    }

    print_tree(stdout, root);
    printf(" = %.2lf\n", eval(root));

    Arena_free(a);
    return 0;
}
#elif defined(FUZZ)
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    Arena *a = Arena_new(8192);
    if (a == NULL)
        return 1;

    Node *root = parse(Data, Size, a);
    if (root == NULL) {
        printf("Parsing failed\n");
        Arena_free(a);
        return 1;
    }

    Arena_free(a);
    return 0;
}

// Docs: https://llvm.org/docs/LibFuzzer.html
#else
int
main(void)
{
    while (true) {
        printf("> ");
        fflush(stdout);

        char buf[1024];
        fgets(buf, sizeof(buf), stdin);

        Arena *a = Arena_new(2048);
        if (a == NULL) {
            printf("Failed to allocate arena\n");
            continue;
        }

        Node *root = parse(buf, strlen(buf), a);
        if (root == NULL) {
            printf("Parsing failed\n");
            Arena_free(a);
            continue;
        }

        print_tree(stdout, root);
        printf(" = %.2lf\n", eval(root));

        Arena_free(a);
    }

    return -1;  // Unreachable
}
#endif
