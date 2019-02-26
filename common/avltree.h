#ifndef _AVLTREE_H_
#define _AVLTREE_H_

//typedef void (*tree_remove_cb) (const char *key, void *val);
//typedef int (*tree_cover_cb) (const char *key, void *newval, void *oldval);
typedef struct node
{
        char* key;
        void* val;
        struct node *left;
        struct node *right;
        struct node *parent;
        int height;
} node_t;

typedef struct tree {
        node_t *root;
        int count;
} tree_t;


tree_t* tree_new();
void** tree_find(tree_t *tree, const char *key);
void* tree_set(tree_t *tree, const char *key, void* val);
void* tree_remove(tree_t* tree, void *key);
void tree_free(tree_t *tree);

#endif
