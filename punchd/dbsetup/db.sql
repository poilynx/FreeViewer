use freeviewer;
drop table if exists user;
create table user(
	id 		integer primary key auto_increment,
	username 	varchar(32),
	passwd		varchar(50) not null,
	lastlogin	timestamp not NULL default CURRENT_TIMESTAMP
) character set utf8;
/* alter table user type=innodb; */
/*
drop trigger if exists t_user_bi_set_username;
create trigger t_user_bi_set_username after insert on user for each row begin update user set username = concat('', after.id) where id = new.id; end;
*/
