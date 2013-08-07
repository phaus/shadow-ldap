#!/usr/bin/env node

var ldap = require('ldapjs');
var bunyan = require('bunyan');

var log = bunyan.createLogger({name: "shadow-ldap"});
var rootDN = 'dc=world';
var server = ldap.createServer();
server.log = log;


server.listen(1389, function() {
  log.info('LDAP server listening at %s', server.url);
});

server.search('', function(req, res, next) {
	var baseObject = {
		dn: '',
		structuralObjectClass: 'OpenLDAProotDSE',
		configContext: 'cn=config',
		attributes: {
			objectclass: ['top', 'OpenLDAProotDS'],
			namingContexts: [rootDN],
			supportedLDAPVersion: ['3'],
			subschemaSubentry:['cn=Subschema']
		}
	};
	console.log("scope "+req.scope+" filter "+req.filter+" baseObject "+req.baseObject);
	if('base' == req.scope 
		&& '(objectclass=*)' == req.filter.toString() 
		&& req.baseObject == ''){
		//log.info(baseObject);
		console.log("return: "+JSON.stringify(baseObject));
		res.send(baseObject);
	} else {
		//log.info(req.toString());
	}

	//log.info('scope: ' + req.scope);
	//log.info('filter: ' + req.filter.toString());
	//log.info('attributes: ' + req.attributes);
	res.end();
});

server.search('cn=Subschema', function(req, res, next) {
	var schema = {
		dn: 'cn=Subschema',
		attributes: {
			objectclass: ['top', 'subentry', 'subschema', 'extensibleObject'],
			cn: ['Subschema']
		}
	};	
	res.send(schema);
	res.end();
});
server.search(rootDN, function(req, res, next) {
	var rootObject = {
		dn: rootDN,
		attributes: {
			objectclass: ['top', 'dcObject', 'organization'],
			hasSubordinates: ['TRUE']
		}
	};
	res.send(rootObject);
	res.end();	
});

