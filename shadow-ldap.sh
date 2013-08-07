#!/usr/bin/env node

var ldap = require('ldapjs');
var parseDN = require('ldapjs').parseDN;
var bunyan = require('bunyan');
var fs = require('fs');

var log = bunyan.createLogger({name: "shadow-ldap"});
var rootDN = 'dc=world';
var passwd_file = 'test/etc/passwd';

function loadPasswdFile(req, res, next) {
  fs.readFile(passwd_file, 'utf8', function(err, data) {
    if (err)
      return next(new ldap.OperationsError(err.message));

    req.users = {};

    var lines = data.split('\n');
    for (var i = 0; i < lines.length; i++) {
      if (!lines[i] || /^#/.test(lines[i]))
        continue;

      var record = lines[i].split(':');
      if (!record || !record.length)
        continue;

      req.users[record[0]] = {
        dn: 'cn=' + record[0] + ', ou=Accounts, '+rootDN,
        attributes: {
          cn: record[0],
          uid: record[2],
          gid: record[3],
          description: record[4],
          homedirectory: record[5],
          shell: record[6] || '',
          objectclass: 'unixUser'
        }
      };
    }

    return next();
  });
}


var pre = [loadPasswdFile];
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
		res.send(baseObject);
	}

	//log.info('scope: ' + req.scope);
	//log.info('filter: ' + req.filter.toString());
	//log.info('attributes: ' + req.attributes);
	res.end();
	return next();
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
	return next();
});

server.search('ou=Accounts,'+rootDN, pre, function(req, res, next) {
  console.log("scope "+req.scope+" filter "+req.filter+" baseObject "+req.baseObject);
  
  // This is for the base call for 'ou=Accounts,'+rootDN
  if('one' == req.scope){
  	//console.log("users: %s", JSON.stringify(req.users));
	Object.keys(req.users).forEach(function(k) {
	if (req.filter.matches(req.users[k].attributes))
		res.send(req.users[k]);
	});
  } 
  if('base' == req.scope){
	var dn = parseDN(req.baseObject.toString());
	//console.log("cn: %s, dn: %s", dn.cn,  JSON.stringify(dn));
	//console.log("sending: %s", JSON.stringify(req.users[dn.rdns[0].cn]));
	res.send(req.users[dn.rdns[0].cn]);
  }

  res.end();
  return next();
});

server.search(rootDN, function(req, res, next) {
	var rootObj = {
		dn: rootDN,
		attributes: {
			objectclass: ['top', 'dcObject', 'organization'],
			hasSubordinates: ['TRUE']
		}
	};
	var rootObjs = [
		{dn: 'cn=admin,'+rootDN, attributes: { objectclass: ['simpleSecurityObject', 'organizationalRole'], hasSubordinates: ['FALSE'] } },
		{dn: 'ou=Accounts,'+rootDN, attributes: { objectclass: ['top', 'organizationalUnit'], hasSubordinates: ['TRUE'] } },
		{dn: 'ou=Groups,'+rootDN, attributes: { objectclass: ['top', 'organizationalUnit'], hasSubordinates: ['TRUE'] } }
	];
	
	if('base' == req.scope 
		&& rootDN == req.baseObject) {
		console.log("scope "+req.scope+" filter "+req.filter+" baseObject "+req.baseObject);
		res.send(rootObj);		
	}
	if('one' == req.scope 
		&& rootDN == req.baseObject) {
		console.log("scope "+req.scope+" filter "+req.filter+" baseObject "+req.baseObject);
		for(var i in rootObjs) {
			res.send(rootObjs[i]);		
		}
	}	
	res.end();	
	return next();
});

