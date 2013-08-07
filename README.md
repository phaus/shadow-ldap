shadow-ldap
===========

A fast way for starting a LDAP Server on a Linux Box.
The LDAP Instance will use the data from 

* _/etc/shadow_ for authentication, 
* _/etc/passwd_ for a user listing
* _/etc/group_ for a group listing.

The only method of supported hashes will be sha-512 (e.g. all Hashes starting with $6$...).

## You need..

First you need to [install node.js](http://nodejs.org/).

Then you need some more modules:

````
npm install ldapjs
npm install bunyan
````
