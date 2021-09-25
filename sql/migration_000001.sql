create table ipgrant (
  id bigint not null primary key auto_increment,
  ipaddr varchar(100) not null,
  svcname varchar(255) not null,
  active tinyint not null default 1,
  created_at datetime(6) default current_timestamp(6) not null,
  index by_ipaddr_x_created_at (ipaddr, created_at)
);

create table allowlist (
  email varchar(255) not null,
  svcname varchar(255) not null,
  created_at datetime(6) default current_timestamp(6) not null,
  primary key (email, svcname)
);

create table svclist (
  svcname varchar(255) not null primary key,
  svcsecret varchar(255) not null,
  created_at datetime(6) default current_timestamp(6) not null
);
