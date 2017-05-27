/* create tables */
CREATE TABLE config(
key text NOT NULL,
value text NOT NULL
);
CREATE TABLE configs_detectors(
primkey int PRIMARY KEY NOT NULL,
detectortype  text NULL,
detector text NULL,
vendor  text NULL,
server  text NULL,
folder text NULL,
file text NULL,
EmailFrom text NULL,
lastevent text NULL,
userid text NULL,
pwd text NULL,
db text NULL,
connectionstring  text NULL,
query1 text NULL,
query2 text NULL
);
CREATE TABLE configs_threatfeed_threatgrid_scoring(
primkey int PRIMARY KEY NOT NULL,
feed_weight text NULL
);
CREATE TABLE configs_threatfeed_virustotal(
key text NULL,
value text NULL
);
CREATE TABLE event_alerts(
primkey int PRIMARY KEY NOT NULL,
timer text NULL,
ip_address text NULL,
hostname text NULL,
timestamp text NULL,
previous_score text NULL,
alert_id text NULL,
detector text NULL,
threat_ip text NULL
);
CREATE TABLE event_machine(
primkey int PRIMARY KEY NOT NULL,
hostname text NULL,
os text NULL,
domain text NULL,
patches_critical text NULL,
patches_high text NULL,
patches_low text NULL,
av_installed text NULL,
av_running text NULL,
av_def_ver text NULL,
bit9_installed text NULL,
bit9_running text NULL,
machine_score text NULL
);
CREATE TABLE event_threat(
primkey int PRIMARY KEY NOT NULL,
threat_dst_ip text NULL,
threat_name text NULL,
threat_score text NULL,
detector text NULL,
threat_url text NULL,
threat_hash text NULL,
time_occurred text NULL,
action_taken text NULL,
file_name text NULL,
threat_status text NULL
);
CREATE TABLE event_user(
primkey int PRIMARY KEY NOT NULL,
username text NULL,
fullname text NULL,
email text NULL,
title text NULL,
dept text NULL,
emp_type text NULL,
emp_phone text NULL,
cube text NULL,
city_state text NULL,
manager text NULL,
manager_title text NULL,
manager_email text NULL,
manager_phone text NULL,
user_score text NULL
);
CREATE TABLE event_whitelist(
primkey int PRIMARY KEY NOT NULL,
artifact text NOT NULL
);
CREATE TABLE previous_threat_hash(
primkey int PRIMARY KEY NOT NULL,
hash text NULL,
timedate text NULL
);
CREATE TABLE previous_threat_ip(
primkey int PRIMARY KEY NOT NULL,
ip text NULL,
timedate text NULL
);
CREATE TABLE previous_threat_url(
primkey int PRIMARY KEY NOT NULL,
url text NULL,
timedate text NULL
);
CREATE TABLE configs_historical_events(
url_query text NULL,
ip_query text NULL,
hash_query text NULL,
url_score int NULL,
ip_score int NULL,
hash_score int NULL,
url_weight int NULL,
ip_weight int NULL,
hash_weight int NULL,
url_incrementer int NULL,
ip_incrementer int NULL,
hash_incrementer int NULL,
url_multiplier int NULL,
ip_multiplier int NULL,
hash_multiplier int NULL
);

/* insert config table keys */
insert into config (key,value) values ('fido.application.teststartup', '');
insert into config (key,value) values ('fido.application.sqltimeout', '');
insert into config (key,value) values ('fido.application.sleepiteration', '');
insert into config (key,value) values ('fido.securityfeed.virustotal.regularweight', '');
insert into config (key,value) values ('fido.application.detectors', '');
insert into config (key,value) values ('fido.email.nonalertemail', '');
insert into config (key,value) values ('fido.director.runinventory', '');
insert into config (key,value) values ('fido.director.virustotal', '');
insert into config (key,value) values ('fido.securityfeed.virustotal.detecteddownloadscore', '');
insert into config (key,value) values ('fido.securityfeed.virustotal.detecteddownloadweight', '');
insert into config (key,value) values ('fido.securityfeed.virustotal.detecteddownloadmultiplier', '');
insert into config (key,value) values ('fido.director.assetscore', '');
insert into config (key,value) values ('fido.posture.asset.paired', '');
insert into config (key,value) values ('fido.posture.asset.hostname', '');
insert into config (key,value) values ('fido.posture.asset.subnet', '');
insert into config (key,value) values ('fido.cyphort.fetch_timewindow', '');
insert into config (key,value) values ('fido.cyphort.max.severity.value', '');
insert into config (key,value) values ('fido.cyphort.max.results.to.fetch', '');
insert into config (key,value) values ('fido.application.fidodb', '');
insert into config (key,value) values ('fido.application.fidodocumentation', '');
insert into config (key,value) values ('fido.director.hostdetection', '');
insert into config (key,value) values ('fido.email.vendor', '');
insert into config (key,value) values ('fido.email.imapserver', '');
insert into config (key,value) values ('fido.email.imapport', '');
insert into config (key,value) values ('fido.email.smtpsvr', '');
insert into config (key,value) values ('fido.email.fidopwd', '');
insert into config (key,value) values ('fido.email.fidoacek', '');
insert into config (key,value) values ('fido.email.fidoemail', '');
insert into config (key,value) values ('fido.email.primaryemail', '');
insert into config (key,value) values ('fido.email.secondaryemail', '');
insert into config (key,value) values ('fido.email.erroremail', '');
insert into config (key,value) values ('fido.email.runerroremail', '');
insert into config (key,value) values ('fido.ldap.basedn', '');
insert into config (key,value) values ('fido.ldap.userid', '');
insert into config (key,value) values ('fido.ldap.pwd', '');
insert into config (key,value) values ('fido.ldap.acek', '');
insert into config (key,value) values ('fido.securityfeed.virustotal.apikey', '');
insert into config (key,value) values ('fido.securityfeed.virustotal.trojanscore', '');
insert into config (key,value) values ('fido.securityfeed.virustotal.trojanweight', '');
insert into config (key,value) values ('fido.securityfeed.virustotal.regularscore', '');

/* insert historical_events table data */
insert into configs_historical_events (url_query,ip_query,hash_query,url_score,ip_score,hash_score,url_weight,ip_weight,hash_weight,url_incrementer) values ('SELECT * FROM previous_threat_url WHERE url = '%url%'','SELECT * FROM previous_threat_ip WHERE ip = '%ip%'','SELECT * FROM previous_threat_hash WHERE hash = '%hash%'','1','1','1','1','1','1','1');