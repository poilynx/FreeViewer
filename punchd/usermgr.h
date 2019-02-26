#ifndef _USERMGR_H_
#define _USERMGR_H_
#define MYSQL_USER "root"
#define MYSQL_PASS "root"
#define MAX_USERNAME 32
#define MAX_PASSWD 41

void usermgr_init();
int usermgr_add_user(const char *username,const char *passwd, char *real_username);
int usermgr_exist_user(const char *username);
int usermgr_delete_user(const char *username);
int usermgr_change_passwd(const char *username, const char *passwd);
int usermgr_check_passwd(const char *username, const char *passwd);
int usermgr_renew(const char *username);
void usermgr_destroy();
void usermgr_clearup();
#endif
