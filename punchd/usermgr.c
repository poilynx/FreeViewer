#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "usermgr.h"
#include <mysql/mysql.h>
#include "log.h"

MYSQL *mysql;
MYSQL_STMT *stmt;


int usermgr_exist_user(const char *username);

void usermgr_init() {
	
	mysql = mysql_init(NULL);
	if(mysql == NULL) {
		log_error("mysql_init");
		exit(-1);
	}
	if(mysql_real_connect(mysql, "127.0.0.1", MYSQL_USER, MYSQL_PASS, "freeviewer", 3306, NULL, 0) == NULL) {
		log_error("mysql_real_connect");
		mysql_close(mysql);
		exit(-1);
	}
	if((stmt = mysql_stmt_init(mysql)) == NULL) {
		log_error("mysql_stmt_init");
		exit(-1);
	}
}

static int hintname_is_valid(const char *name) {
	if(*name == '0')
		return 1;
	for(const char *p =name; *p; p++) {
		if(*p < '0' || *p > '9') {
			return 1;
		}
	}
	return 0;
}
int usermgr_add_user(const char *username,const char *passwd, char *real_username) {
	assert(passwd);
	assert(real_username);
	const char 
		*query = "insert into user (username, passwd) values (NULL,?);",
		*query_update = "update user set username = ? where id = ?";
	unsigned int id;
	char username_buffer[32];
	MYSQL_BIND param[2];
	memset(param, 0, sizeof(param));

	unsigned long username_len , passwd_len = strlen(passwd);

	memset(param, 0, sizeof(param));

	if(mysql_stmt_prepare(stmt, query, strlen(query))) {
		log_error("mysql_stmt_prepare:%s", mysql_stmt_error(stmt));
		exit(-1);
	}


	//mysql_stmt_param_count(stmt);
	param[0].buffer_type = MYSQL_TYPE_STRING;
	param[0].buffer_length = passwd_len+1;
	param[0].is_null = 0;
	param[0].length = &passwd_len;
	param[0].buffer = (char*)passwd;
	
	
	if(mysql_stmt_bind_param(stmt, param)) {
		log_error("mysql_stmt_bind_param:%s", mysql_stmt_error(stmt));
		exit(-1);
	}

	if(mysql_query(mysql, "start transaction")) {
		log_error("mysql_query:%s", mysql_stmt_error(stmt));
		exit(-1);
	}

	if(mysql_stmt_execute(stmt)) {
		log_error("mysql_stmt_execute:%s", mysql_stmt_error(stmt));
		exit(-1);
	}

	id = mysql_insert_id(mysql);

	if(username && hintname_is_valid(username) && !usermgr_exist_user(username)) { /* NOTICE: usermgr_exist_user call must be put in the correctly location */
		strcpy(username_buffer, username);
	} else {
		sprintf(username_buffer, "%d", id);
	}

	if(mysql_stmt_prepare(stmt, query_update, strlen(query_update))) {
		log_error("mysql_stmt_prepare:%s", mysql_stmt_error(stmt));
		exit(-1);
	}

	memset(param, 0, sizeof(param));

	param[0].buffer_type = MYSQL_TYPE_STRING;
	param[0].buffer_length = sizeof(username_buffer);
	param[0].buffer = (char*)username_buffer;
	param[0].length = &username_len;

	param[1].buffer_type = MYSQL_TYPE_LONG;
	param[1].buffer_length = 0;
	param[1].buffer = &id;
	param[1].is_null = 0;
	param[1].length = 0;

	username_len = strlen(username_buffer);

	if(mysql_stmt_bind_param(stmt, param)) {
		mysql_query(mysql, "rollback");
		log_error("mysql_stmt_bind_param:%s", mysql_stmt_error(stmt));
		exit(-1);
	}

	if(mysql_stmt_execute(stmt)) {
		mysql_query(mysql, "rollback");
		log_error("mysql_stmt_prepare:%s", mysql_stmt_error(stmt));
		exit(-1);
	}

	if(mysql_query(mysql, "commit")) {
		mysql_query(mysql, "rollback");
		log_error("mysql_query:%s", mysql_error(mysql));
		exit(-1);
	}
	
	strcpy(real_username, username_buffer);
	return 0;
}

int usermgr_exist_user(const char *username) {
	const char query[] = "select count(id) from user where username = ? for update";
	unsigned long username_len = strlen(username);
	MYSQL_BIND param[1] = {{0}};
	int res;
	my_bool error, is_null;
	unsigned long length;

	param[0].buffer_type = MYSQL_TYPE_STRING;
	param[0].buffer = (void*)username;
	param[0].length = &username_len;
	param[0].buffer_length = username_len + 1;
	if(mysql_stmt_prepare(stmt, query, sizeof(query))) {
		log_error("mysql_stmt_prepare:%s", mysql_stmt_error(stmt));
		exit(-1);
	}

	if(mysql_stmt_bind_param(stmt, param)) {
		log_error("mysql_stmt_bind_param:%s", mysql_stmt_error(stmt));
		exit(-1);
	}

	if(mysql_stmt_execute(stmt)) {
		log_error("mysql_stmt_execute:%s", mysql_stmt_error(stmt));
		exit(-1);
	}

	
	param[0].buffer_type = MYSQL_TYPE_LONG;
	param[0].buffer = (char*)&res;
	param[0].is_null = &is_null;
	param[0].length = &length;
	param[0].error = &error;

	if(mysql_stmt_bind_result(stmt, param)) {
		log_error("mysql_stmt_bind_result:%d", mysql_stmt_error(stmt));
		exit(-1);
	}

	if(mysql_stmt_store_result(stmt)) {
		log_error("mysql_stmt_store_result:%d", mysql_stmt_error(stmt));
		exit(-1);
	}

	if(mysql_stmt_fetch(stmt))
		return 0;

	return res;
}

int usermgr_delete_user(const char *username) {
	const char * query = "delete from user where username = ?;";
	int affected_rows;
	MYSQL_BIND param[1]={{0}};
	unsigned long username_len = strlen(username);

	if(mysql_stmt_prepare(stmt, query, strlen(query))) {
		log_error("mysql_stmp_prepare");
		exit(-1);
	}

	param[0].buffer_type = MYSQL_TYPE_STRING;
	param[0].buffer_length = username_len+1;
	param[0].is_null = 0;
	param[0].length = &username_len;
	param[0].buffer = (char*)username;

	if(mysql_stmt_bind_param(stmt, param)) {
		log_error("mysql_stmt_bind_param:%s", mysql_stmt_error(stmt));
		exit(-1);
	}

	if(mysql_stmt_execute(stmt)) {
		log_error("mysql_stmt_execute:%s", mysql_stmt_error(stmt));
		exit(-1);
	}

	affected_rows = mysql_stmt_affected_rows(stmt);
	if(affected_rows != 1)
		return -1;
	return 0;

}

int usermgr_change_passwd(const char *username, const char *passwd) {
	assert(username);
	assert(passwd);

	const char *query_update = "update user set passwd = ? where username = ?";
	MYSQL_BIND param[2];
	memset(param, 0, sizeof(param));

	unsigned long username_len = strlen(username), passwd_len = strlen(passwd);

	if(mysql_stmt_prepare(stmt, query_update, strlen(query_update))) {
		log_error("mysql_stmt_prepare:%s", mysql_stmt_error(stmt));
		exit(-1);
	}

	param[0].buffer_type = MYSQL_TYPE_STRING;
	param[0].buffer_length = passwd_len+1;
	param[0].is_null = 0;
	param[0].buffer = (char*)passwd;
	param[0].length = &passwd_len;
	
	param[1].buffer_type = MYSQL_TYPE_STRING;
	param[1].buffer_length = username_len+1;
	param[1].is_null = 0;
	param[1].buffer = (char*)username;
	param[1].length = &username_len;

	if(mysql_stmt_bind_param(stmt, param)) {
		log_error("mysql_stmt_bind_param:%s", mysql_stmt_error(stmt));
		exit(-1);
	}

	if(mysql_stmt_execute(stmt)) {
		log_error("mysql_stmt_prepare:%s", mysql_stmt_error(stmt));
		exit(-1);
	}
	if(mysql_stmt_affected_rows(stmt) != 1)
		return 1;

	return 0;
}

/* ret 0 if correctly */
int usermgr_check_passwd(const char *username, const char *passwd) {
	const char query[] = "select passwd from user where username = ?";
	char passwd_buffer[MAX_PASSWD];
	unsigned long username_len = strlen(username);
	MYSQL_BIND param[1] = {{0}};
	unsigned long length;
	my_bool is_null, error;

	param[0].buffer_type = MYSQL_TYPE_STRING;
	param[0].buffer = (char*)username;
	param[0].length = &username_len;
	param[0].buffer_length = username_len + 1;

	if(mysql_stmt_prepare(stmt, query, sizeof(query))) {
		log_error("mysql_stmt_prepare:%s", mysql_stmt_error(stmt));
		exit(-1);
	}

	if(mysql_stmt_bind_param(stmt, param)) {
		log_error("mysql_stmt_bind_param:%s", mysql_stmt_error(stmt));
		exit(-1);
	}

	if(mysql_stmt_execute(stmt)) {
		log_error("mysql_stmt_execute:%s", mysql_stmt_error(stmt));
		exit(-1);
	}

	
	param[0].buffer_type = MYSQL_TYPE_STRING;
	param[0].buffer = (char*)&passwd_buffer;
	param[0].buffer_length = sizeof(passwd_buffer);
	param[0].is_null = &is_null;
	param[0].length = &length;
	param[0].error = &error;

	if(mysql_stmt_bind_result(stmt, param)) {
		log_error("mysql_stmt_bind_result:%d", mysql_stmt_error(stmt));
		exit(-1);
	}

	if(mysql_stmt_store_result(stmt)) {
		log_error("mysql_stmt_store_result:%d", mysql_stmt_error(stmt));
		exit(-1);
	}

	assert(mysql_stmt_num_rows(stmt) <= 1);

	if(mysql_stmt_num_rows(stmt) != 1) {
		return 1;
	}

	mysql_stmt_fetch(stmt);

	if(strcmp(passwd, passwd_buffer) != 0) {
		return 1;
	}
	return 0;

}

int usermgr_renew(const char *username) {
	assert(username);
	const char *query = "update user set lastlogin = now() where username = ?;";
	int affected_rows;
	MYSQL_BIND param[1]={{0}};
	unsigned long username_len = strlen(username);

	if(mysql_stmt_prepare(stmt, query, strlen(query))) {
		log_error("mysql_stmp_prepare: %s", mysql_stmt_error(stmt));
		exit(-1);
	}

	param[0].buffer_type = MYSQL_TYPE_STRING;
	param[0].buffer_length = username_len+1;
	param[0].is_null = 0;
	param[0].length = &username_len;
	param[0].buffer = (char*)username;

	if(mysql_stmt_bind_param(stmt, param)) {
		log_error("mysql_stmt_bind_param:%s", mysql_stmt_error(stmt));
		exit(-1);
	}

	if(mysql_stmt_execute(stmt)) {
		log_error("mysql_stmt_execute:%s", mysql_stmt_error(stmt));
		exit(-1);
	}

	affected_rows = mysql_stmt_affected_rows(stmt);

	assert(affected_rows < 2);

	if(affected_rows != 1)
		return -1;
	return 0;
}

void usermgr_destroy() {
	mysql_stmt_close(stmt);
	mysql_close(mysql);
}

void usermgr_clearup() {
	const char * query_delete = "delete from user where lastlogin < date_sub(now(), interval 7 day)";
	if(mysql_query(mysql, query_delete)) {
		log_error("mysql_query:%s", mysql_error(mysql));
		exit(-1);
	}
}	

void usermgr_test() {
	char name[MAX_USERNAME] = "abc";
	char pass[MAX_PASSWD] = "123";
	char realname[MAX_USERNAME];
	usermgr_init();
	assert(usermgr_add_user(name,pass, realname) == 0);
	assert(usermgr_check_passwd(realname,pass) == 0);
	assert(usermgr_change_passwd(realname, "456") == 0);
	assert(usermgr_check_passwd(realname, "456") == 0);
	assert(usermgr_exist_user(name) == 1);
	assert(usermgr_add_user(name,pass, realname) == 0);
	assert(usermgr_exist_user(realname) == 1);
	assert(usermgr_delete_user(realname) == 0);
	assert(usermgr_exist_user(realname) == 0);
	assert(usermgr_add_user(NULL,pass, realname) == 0);
	assert(usermgr_exist_user(realname) == 1);
	assert(usermgr_delete_user(realname) == 0);
	assert(usermgr_delete_user(name) == 0);
}
//void main() {usermgr_test();}
//gcc usermgr.c -lmysqlclient ../common/log.c -I../common/
