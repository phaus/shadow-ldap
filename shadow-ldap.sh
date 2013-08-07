#!/usr/bin/env node

var ldap = require('ldapjs');
var parseDN = require('ldapjs').parseDN;
var bunyan = require('bunyan');
var fs = require('fs');

var log = bunyan.createLogger({name: "shadow-ldap"});

// move to configuration file.
var rootDN = 'dc=world';
var passwd_file = 'test/etc/passwd';
var group_file = 'test/etc/group';

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
        dn: 'uid=' + record[0] + ', ou=Accounts, '+rootDN,
        attributes: {
          uid: record[0],
          uidNumber: record[2],
          gidNumber: record[3],
          description: record[4],
          homeDirectory: record[5],
          loginShell: record[6] || '',
          objectclass: ['top', 'posixAccount']
        }
      };
    }

    return next();
  });
}

function loadGroupFile(req, res, next) {
	fs.readFile(group_file, 'utf8', function(err, data) {
    if (err)
		return next(new ldap.OperationsError(err.message));

	req.groups = {};
 	var lines = data.split('\n');
    for (var i = 0; i < lines.length; i++) {
		if (!lines[i] || /^#/.test(lines[i]))
        	continue;
     	var record = lines[i].split(':');
      	if (!record || !record.length)
        	continue;  
       	// sasl:x:45:smmta,smmsp
       	var members = record[3].split(',');
       	if (!members || !members.length)
        	continue; 	 
    	req.groups[record[0]] = { 	
       		dn: 'cn=' + record[0] + ', ou=Groups, '+rootDN,	
       		attributes: {
       			cn: record[0],
       			gidNumber: record[2],
       			memberUid: members.length > 1 ? members : [record[0]],
       			objectclass: ['top', 'posixGroup']	
       		}
       	};
    }
    return next();
  });	
}

var preUsers = [loadPasswdFile];
var preGroups = [loadGroupFile];
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


server.search('ou=Groups,'+rootDN, preGroups, function(req, res, next) {
	console.log("scope "+req.scope+" filter "+req.filter+" baseObject "+req.baseObject);
  	if('one' == req.scope) { // List Call for Groups 
  		//console.log("groups: %s", JSON.stringify(req.groups));
		Object.keys(req.groups).forEach(function(k) {
		if (req.filter.matches(req.groups[k].attributes))
			res.send(req.groups[k]);
		});
  	} else if(req.baseObject.toString().indexOf('ou=Groups, '+rootDN) == 0) {  // Base Call for Groups
  		var ou = {dn: 'ou=Groups,'+rootDN, attributes: { objectclass: ['top', 'organizationalUnit'], hasSubordinates: ['TRUE'] } };
  		res.send(ou);
  	} else {
		var dn = parseDN(req.baseObject.toString());  // Call for Groups Subs
		//console.log("uid: %s, dn: %s", dn.uid,  JSON.stringify(dn));
		//console.log("sending: %s", JSON.stringify(req.groups[dn.rdns[0].cn]));
		res.send(req.groups[dn.rdns[0].cn]);
  	}
  	res.end();
  	return next();
});

server.search('ou=Accounts,'+rootDN, preUsers, function(req, res, next) {
	console.log("scope "+req.scope+" filter "+req.filter+" baseObject "+req.baseObject);
  
  	if('one' == req.scope) { // List Call for Accounts 
  		//console.log("users: %s", JSON.stringify(req.users));
		Object.keys(req.users).forEach(function(k) {
		if (req.filter.matches(req.users[k].attributes))
			res.send(req.users[k]);
		});
  	} else if(req.baseObject.toString().indexOf('ou=Accounts, '+rootDN) == 0) {  // Base Call for Accounts
  		var ou = {dn: 'ou=Accounts,'+rootDN, attributes: { objectclass: ['top', 'organizationalUnit'], hasSubordinates: ['TRUE'] } };
  		res.send(ou);
  	} else {
		var dn = parseDN(req.baseObject.toString());  // Call for Accounts Subs
		//console.log("uid: %s, dn: %s", dn.uid,  JSON.stringify(dn));
		//console.log("sending: %s", JSON.stringify(req.users[dn.rdns[0].uid]));
		res.send(req.users[dn.rdns[0].uid]);
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

