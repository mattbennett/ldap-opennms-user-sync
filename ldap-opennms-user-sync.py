#!/usr/bin/python
"""
	LDAP User Synchronization for OpenNMS via ActiveDirectory
"""
#python 2.5 support
from __future__ import with_statement

import re
import sys
import ldap
import time

from optparse import OptionParser

from BeautifulSoup import BeautifulStoneSoup

#######################################################################
# BEGIN CONFIG

USE_SSL = True
SSL_CERT_DIR = "/etc/ssl/certs"

HOST = 'localhost'
USERNAME = 'ldapuser'
PASSWORD = 'password'

DOMAIN = 'example.com'
BASE_DN = 'ou=users,dc=example,dc=com'
MEMBER_GROUPS = ('opennmsusers','opennmsadmins')

INPUT_PATH = 'users.xml'
OUTPUT_PATH = INPUT_PATH


#Replace {{ property }} with appropriate mapping for your LDAP server 
USER_TEMPLATE = """
	<user read-only="true">
		<user-id xmlns="">{{sAMAccountName}}</user-id>
		<full-name xmlns="">{{cn}}</full-name>
		<user-comments xmlns="">LDAP Account for {{cn}}</user-comments>
		<password xmlns="">!</password>
		<contact type="email" info="{{mail}}"/>
		<contact type="pagerEmail" info="{{pager}}"/>
		<contact type="xmppAddress" info=""/>
		<contact type="microblog" info=""/>
		<contact type="numericPage" info="" serviceProvider=""/>
		<contact type="textPage" info="" serviceProvider=""/>
		<contact type="workPhone" info="{{telephoneNumber}}"/>
		<contact type="mobilePhone" info="{{mobile}}"/>
		<contact type="homePhone" info="{{homePhone}}"/>
		<tui-pin xmlns="">0</tui-pin>
	</user>
"""
# END CONFIG
#######################################################################


def bind(username, password, host, domain):
	"""
		Bind to ActiveDirectory
	"""
	ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, 10) 
	ldap.set_option(ldap.OPT_REFERRALS, 0)
	ldap.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
	proto = "ldap"
	if USE_SSL:
		ldap.set_option(ldap.OPT_X_TLS_CACERTDIR, SSL_CERT_DIR)
		proto += "s"
	con = ldap.initialize('%s://%s' % (proto, host))
	con.simple_bind_s('%s@%s' % (username, domain), password)
	
	return con


def search(con, baseDN, searchScope=ldap.SCOPE_SUBTREE, searchFilter=u'(objectClass=user)', retrieveAttributes=None):
	"""
		Search ActiveDirectory
	"""
	result_set = []
	try:
		ldap_result_id = con.search(baseDN, searchScope, searchFilter, retrieveAttributes)
		while 1:
			result_type, result_data = con.result(ldap_result_id, 0)
			if (result_data == []):
				break
			else: 
				if result_type == ldap.RES_SEARCH_ENTRY:
					result_set.append(result_data[0])
	except ldap.LDAPError, e:
		print e
	
	return result_set


def add_user_tag(basesoup, data):
	"""
		Renders USER_TEMPLATE using the supplied data
		Adds it as a <user/> tag to the users.xml soup
	"""
	renderer = [( re.compile('{{(\w+)}}'), lambda match: data.get(match.group(1),[''])[0] )]	
	usersoup = BeautifulStoneSoup(USER_TEMPLATE, markupMassage=renderer, selfClosingTags=['contact'])
	basesoup.users.insert(0, usersoup.user)


def main():
	"""
	"""
	#process options
	usage = "Usage: %prog [options] arg"
	parser = OptionParser(usage)
	parser.add_option("-d", "--dry-run", dest="dry_run", help="don't actually write the output file", action="store_true", default=False)
	(options, args) = parser.parse_args()
    
	#parse the xml file with beautifulsoup
	with open(INPUT_PATH) as fh:
		soup = BeautifulStoneSoup(fh.read(), selfClosingTags=['contact'])
	
	#purge read-only (i.e. LDAP) users from the XML soup
	for user in soup.findAll('user', attrs={'read-only':'true'}):
		user.extract()
	
	#connect to ldap, get list of users
	con = bind(USERNAME, PASSWORD, HOST, DOMAIN)
	if globals().has_key('MEMBER_GROUPS'):
		memberships = []
		for group in MEMBER_GROUPS:
			memberships.append("(memberOf=cn=%s,%s)" % (group, BASE_DN))
		users = search(con, BASE_DN, searchFilter=u'(|%s)' % "".join(memberships))
	else:
		users = search(con, BASE_DN)

	#add user tag for each user in list to the XML soup
	for user in users:
		dn, attrs = user
		add_user_tag(soup, attrs)
	
	#update timestamp
	soup.find('created').string.replaceWith(time.strftime("%A, %d %B %Y %H:%M:%S o'clock %Z"))
	
	#BeautifulSoup / SGMLParser will lowercase 'serviceProvider' because all attributes in XML
	#should be lowercase. But OpenNMS is case-sensitive, so we force it back to being broken
	out = re.sub("serviceprovider", "serviceProvider", soup.prettify())
	
	#write file or show what we would've written
	if not options.dry_run:
		with open(OUTPUT_PATH, 'w') as fh:
			fh.write(out)
	else:
		print "Generated:\n"
		print out
		
	return 0

if __name__ == "__main__":
	sys.exit(main())
