#include "avltree.h"
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
static void check_tree(node_t *node) {
	if(!node) return;
	else {
		if(node->left) assert(strcmp(node->left->key, node->key) < 0);
		if(node->right) assert(strcmp(node->right->key, node->key) > 0);
	}
}

void _remove_cb(const char *key, void *val) {
	//free(val);
}
int _cover_cb(const char *key, void *newval,void *oldval) {
	free(oldval);
	return 0;
}
int main() {
	char buf[32];
	tree_t tree;
	tree_init(&tree,_remove_cb,_cover_cb);
	node_t *p;
	void * val;
	long i,r;
	for(i = 0; i<30; i++) {
		sprintf(buf,"%ld", i);
		assert(tree_set(&tree, buf, strdup(buf)) == 0);
	}
	assert(tree.count == 30);
	for(i = 0; i<30; i++) {
		sprintf(buf, "%ld", i);
		assert(tree_find(&tree, buf, &val) == 1);
		assert(strcmp(val, buf) == 0);
		check_tree(tree.root);
	}
	sprintf(buf, "31");
	assert(tree_find(&tree, buf, &val) == 0);
	assert(tree.count == 30);

	for(i=0;i<30;i++) {
		sprintf(buf,"%ld", i);
		assert(tree_find(&tree, buf, &val) == 1);
		assert(tree_remove(&tree, buf) == 0);
		assert(tree_find(&tree, buf, &val) == 0);
	}
	assert(tree.count == 0);

	printf("All test complate.\n");
	return 0;

}
