#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define _AVLTREE_C_IGN_
#include "avltree.h"
#undef _AVLTREE_C_IGN_
#if 0
static void print_tree_indent(node_t *node, int indent);
static void print_tree(node_t *node);
#endif 

static int max(int a, int b) { return a > b ? a : b; }

static node_t *find(node_t *root,const char *key)
{

	if (root == NULL) return NULL;
	if (strcmp(key,root->key) < 0)
		return find(root->left, key);
	else if (strcmp(key, root->key) > 0)
		return find(root->right, key);
	else
		return root;
}


static int height(node_t *root)
{
	return root ? root->height : 0;
}

static void adjust_height(node_t *root)
{
	root->height = 1 + max(height(root->left), height(root->right));
	//printf("adjust_height(node) -> %d\n",root->height);
}

/* We can assume node->left is non-null due to how this is called */
static node_t *rotate_right(node_t *root)
{
	/* Fix pointers */
	node_t *new_root = root->left;
	if (root->parent)
	{
		if (root->parent->left == root) root->parent->left = new_root;
		else root->parent->right = new_root;
	}
	new_root->parent = root->parent;
	root->parent = new_root;
	root->left = new_root->right;
	if (root->left) root->left->parent = root;
	new_root->right = root;

	/* Fix heights; root and new_root may be wrong. Do bottom-up */
	adjust_height(root);
	adjust_height(new_root);
	return new_root;
}

/* We can assume node->right is non-null due to how this is called */
static node_t *rotate_left(node_t *root)
{
	/* Fix pointers */
	node_t *new_root = root->right;
	if (root->parent)
	{
		if (root->parent->right == root) root->parent->right = new_root;
		else root->parent->left = new_root;
	}
	new_root->parent = root->parent;
	root->parent = new_root;
	root->right = new_root->left;
	if (root->right) root->right->parent = root;
	new_root->left = root;

	/* Fix heights; root and new_root may be wrong */
	adjust_height(root);
	adjust_height(new_root);
	return new_root;
}

static node_t *make_node(const char *key, void *val, node_t *parent)
{
	node_t *n = malloc(sizeof(node_t));
	n->key = strdup(key);
	n->val = val;
	n->parent = parent;
	n->height = 1;
	n->left = NULL;
	n->right = NULL;

	return n;
}

static node_t *balance(node_t *root)
{
	if (height(root->left) - height(root->right) > 1)
	{
		if (height(root->left->left) > height(root->left->right))
		{
			root = rotate_right(root);
		}
		else
		{
			//root->left = rotate_left(root->left);
			rotate_left(root->left);
			root = rotate_right(root);
		}
	}
	else if (height(root->right) - height(root->left) > 1)
	{
		if (height(root->right->right) > height(root->right->left))
		{
			root = rotate_left(root);
		}
		else
		{
			//root->right = rotate_right(root->right);
			rotate_right(root->right);
			root = rotate_left(root);
		}
	}
	return root;
}



/* To remove specified node, fill `effect' with the pointer of lowest unblanced child node pointer*/

/* It will not to balance and adjust height */
static node_t* rmnode(node_t* node) {
	node_t * new_node = node, **pnode = NULL;
	if(node->parent) {
		if(node->parent->left == node)
			pnode = &node->parent->left;
		else
			pnode = &node->parent->right;
	}
	
	if(node->left == NULL && node->right == NULL) {
		if(pnode) {
			*pnode = NULL;
		}
		//free node
		new_node = node->parent;
	} else if(node->left == NULL) {
		node->right->parent = node->parent;
		if(pnode) {
			*pnode = node->right;
		}
		// free node
		new_node = node->right;
		//*effect = new_node->parent = node->parent;
	} else if(node->right == NULL) {
		node->left->parent = node->parent;
		if(pnode) {
			*pnode = node->left;
		}
		// free node
		new_node = node->left;
	} else {
		/* gtnode is right+leftest child node */
		node_t * gtnode = node->right; 
		char * tmpkey;
		while(gtnode->left) gtnode = gtnode->left;

		/* Exchange key pointer in gtnode and node*/
		tmpkey = node->key;
		node->key = gtnode->key;
		gtnode->key = tmpkey;

		node->val = gtnode->val; //node->val already clean in `remove' callback

		if(gtnode->parent == node) {
			node->right = gtnode->right;
			if(gtnode->right) gtnode->right->parent = node; 
			new_node = node;
		} else {
			gtnode->parent->left = gtnode->right;
			if(gtnode->right) gtnode->right->parent = gtnode->parent;
			new_node = gtnode->parent;

		}
		node = gtnode; // to free node
	}
	free(node->key);
	free(node);
	return new_node;
}



static void remove_child(node_t *node) {
	if (node) {
		remove_child(node->left);
		remove_child(node->right);
		free(node);
	}
}

void** tree_find(tree_t *tree, const char *key) {
	node_t *node = find(tree->root, key);
	if(node != NULL) {
		return  &node->val;
	} else 
		return NULL;
		
}

tree_t *tree_new() {
	tree_t *tree = malloc(sizeof(tree_t));
	if(tree == NULL) {
		perror("malloc");
		exit(-1);
	}

	tree->root = NULL;
	tree->count = 0;
	return tree;
}


void* tree_set(tree_t *tree, const char *key, void* val)
{
	void *oldval;
	node_t *current = tree->root;

	if(tree->count == 0) {
		tree->root = make_node(key, val, NULL);
		tree->count = 1;
		return 0;
	}

	while (strcmp(current->key, key) != 0) {
		if (strcmp(key,current->key) < 0) {
			if (current->left)
				current = current->left;
			else {
				current->left = make_node(key, val, current);
				current = current->left;
			}
		} else if (strcmp(key, current->key) > 0) {
			if (current->right) 
				current = current->right;
			else {
				current->right = make_node(key, val, current);
				current = current->right;
			}
		} else {
			oldval = current->val;
			current->val = val;/* Value was in the tree, update*/
			return oldval;
#if 0
			if(tree->cover_cb == NULL || tree->cover_cb(current->key, current->val, val) == 0) {
				current->val = val;/* Value was in the tree, update*/
				return 0; 
			} else {
				return 1;
			}
#endif
		}
	}
	tree->count ++;
	do {
		current  = current->parent;
		adjust_height(current);
		current = balance(current);
	} while (current->parent);
	tree->root = current;


	return NULL;
}

void* tree_remove(tree_t* tree, void *key) {
	node_t * current = tree->root;
	void *oldval;

	//if(tree->count == 0) return NULL; /* Empty */


	while(current) {
		if(strcmp((current)->key, key) > 0) {
			current = current->left;
		} else if(strcmp((current)->key, key) < 0) {
			current = current->right;
		} else {
			node_t * pre = NULL;

			oldval = current->val;
			current = rmnode(current);

			tree->count --;
			while(current) {
				adjust_height(current);
				current = balance(current); 
				pre = current;
				current = current->parent;
			}
			tree->root = pre;
			return oldval;
		}
	}

	/* Not found */
	return NULL;
}

void tree_free(tree_t* tree) {
	assert(tree);
	remove_child(tree->root);
	free(tree);
}

#if 0
/* Tests to make sure above code actually works */
static void print_tree_indent(node_t *node, int indent)
{
	int ix;
	for (ix = 0; ix < indent; ix++) printf(" ");
	if (!node) printf("Empty child\n");
	else
	{
		printf("[%s]<-%s:%d\n", node->key, node->parent?node->parent->key:"NIL", node->height);
		print_tree_indent(node->left, indent + 4);
		print_tree_indent(node->right, indent + 4);
	}
}
static void print_tree(node_t *node) {
	print_tree_indent(node, 0);
}
#endif


