INSERT INTO oauth_client_details
	(client_id, client_secret, scope, authorized_grant_types,
	web_server_redirect_uri, authorities, access_token_validity,
	refresh_token_validity, additional_information, autoapprove)
VALUES
	('fooClientIdPassword', '{bcrypt}$2a$10$jhtH283TX/TOFwhq5BRCAujoMApGI1nXcuoqmYJgKjObYjazJKVgu', 'foo,read,write',
	'password,authorization_code,refresh_token', null, null, 36000, 36000, null, true);
INSERT INTO oauth_client_details
	(client_id, client_secret, scope, authorized_grant_types,
	web_server_redirect_uri, authorities, access_token_validity,
	refresh_token_validity, additional_information, autoapprove)
VALUES
	('sampleClientId', '{bcrypt}$2a$10$jhtH283TX/TOFwhq5BRCAujoMApGI1nXcuoqmYJgKjObYjazJKVgu', 'read,write,foo,bar',
	'implicit', null, null, 36000, 36000, null, false);
INSERT INTO oauth_client_details
	(client_id, client_secret, scope, authorized_grant_types,
	web_server_redirect_uri, authorities, access_token_validity,
	refresh_token_validity, additional_information, autoapprove)
VALUES
	('barClientIdPassword', '{bcrypt}$2a$10$jhtH283TX/TOFwhq5BRCAujoMApGI1nXcuoqmYJgKjObYjazJKVgu', 'bar,read,write',
	'password,authorization_code,refresh_token', null, null, 36000, 36000, null, true);
