#!/usr/bin/env python

#User variables
ad = ""
#Access domain
pd = ""
#Primary domain
db = ""
#Datbase user
dbpass = ""
#Database password

import sys
import os
import subprocess
import random
import re
import string
import pwd
import grp
import shutil
import imaplib
import getpass
from xml.dom import minidom

import scriptutil


############################################
####Begin standalone function definitions###
############################################
def setup_keys(uname, host):
    """Setup required ssh-keys"""
    print ""
    print "#" * 44
    print "Enter your Server Administrator SSH Password"
    print "#" * 44
    key = os.environ['HOME']+"/.ssh/id_rsa"
    if os.path.isfile(key) == False:
        tmp = subprocess.call(['ssh-keygen', '-t', 'rsa', '-N', '', '-C', "Created by (gs) to (dv) migration script", '-f', key])
    pipe = subprocess.Popen(["ssh-copy-id", "-i", key+".pub", uname+"@"+host], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = list(pipe.communicate())
    out.append(pipe.returncode)
    return out

def valid_access_domain(access_domain):
    val = re.compile(r's\d{3,6}\.gridserver.com')
    if val.match(access_domain):
        return True
    else:
        return False

def get_siteid(access_domain):
    p = re.compile(r's(\d+)\.gridserver.com')
    if p:
        s = p.search(access_domain)
        if s:
            return s.group(1)

def standard_database_user(dbuser):
    val = re.compile(r'db\d{3,6}')
    if val.match(dbuser):
        return True

def valid_source(path):
    val = re.compile(r'domains/[\w.-]+/html/')
    if val.match(path):
        tmp = val.match(path).span()
        if tmp == (0, len(path)):
            return True

def valid_domain(domain):
    val = re.compile(r'^([a-z0-9]([-a-z0-9]*[a-z0-9])?\.)+((a[cdefgilmnoqrstuwxz]|aero|arpa)|(b[abdefghijmnorstvwyz]|biz)|(c[acdfghiklmnorsuvxyz]|cat|com|coop)|d[ejkmoz]|(e[ceghrstu]|edu)|f[ijkmor]|(g[abdefghilmnpqrstuwy]|gov)|h[kmnrtu]|(i[delmnoqrst]|info|int)|(j[emop]|jobs)|k[eghimnprwyz]|l[abcikrstuvy]|(m[acdghklmnopqrstuvwxyz]|mil|mobi|museum)|(n[acefgilopruz]|name|net)|(om|org)|(p[aefghklmnrstwy]|pro)|qa|r[eouw]|s[abcdeghijklmnortvyz]|(t[cdfghjklmnoprtvwz]|travel)|u[agkmsyz]|v[aceginu]|w[fs]|y[etu]|z[amw])$')
    if val.match(domain):
        return True
    else:
        return False

def ssh_works(uname, host):
    pipe = subprocess.Popen(['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no', uname + '@' + host, 'exit'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = list(pipe.communicate())
    out.append(pipe.returncode)
    if out[2] == 0:
        return True
    else:
        return False
    
def ssh(cmd, uname, host):
    """Runs a command remotely with ssh and returns the output"""
    run = ['ssh ' + uname+'@'+host + ' ' + '"'+cmd+'"']
    pipe = subprocess.Popen(run, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    out = list(pipe.communicate())
    out.append(pipe.returncode)
    return out

def rchown(path, user=-1, group=-1):
    if user != -1:
        uid = pwd.getpwnam(user)[2]
    if group != -1:
        gid = grp.getgrnam(group)[2]
    for root, dirs, files in os.walk(path):
        os.chown(root, uid, gid)
        for f in files:
            os.chown(os.path.join(root,f), uid, gid)
    return root, dirs, files

def chown(path, user=-1, group=-1):
    if user != -1:
        uid = pwd.getpwnam(user)[2]
    if group != -1:
        gid = grp.getgrnam(group)[2]
    tmp = os.chown(path, uid, gid)
    return tmp

def kill_skel(path):
    shutil.rmtree(os.path.join(path, "test"))
    shutil.rmtree(os.path.join(path, "img"))
    os.remove(os.path.join(path, "css/style.css"))
    os.remove(os.path.join(path, "css/tabs.css"))
    os.remove(os.path.join(path, "css/winxp.blue.css"))
    os.rmdir(os.path.join(path, "css"))
    os.remove(os.path.join(path, "favicon.ico"))
    os.remove(os.path.join(path, "index.html"))
    return

def get_list(user, host):
    """Returns the contents of the domains folder, using -F to show types"""
    tmp = ssh('ls -F domains/', user, host)
    raw = tmp[0].splitlines()
    return raw

def get_emails(primary_domain, access_domain):
    """Returns the contents of the emails folder"""
    tmp = ssh('ls ..', primary_domain, access_domain)
    raw = tmp[0].splitlines()
    email_list = [e.replace('%', '@') for e in raw]
    #Throws the access domain on the end of all-domains addresses. This is a simple way to guarantee that we will log into the correct account later.
    for i in range(0, len(email_list)):
        if email_list[i].find('@') == -1:
            email_list[i] = email_list[i] + '@' + access_domain
    emails = {}
    for e in email_list:
        emails[e] = 'ENTER PASSWORD HERE'
    return emails

def migrate_email(src, tgt):
    folders = src.list_folders()
    for f in folders:
        tmp = tgt.make_folder(f)
        print tmp
        tmp = tgt.subscribe(f)
        print tmp
    for f in folders:
        messages = src.list_messages(f)
        for m in messages:
            move = src.fetch_message(f, m)
            tmp = tgt.add_message(f, move)
            print tmp
    return

def create_email_account(user, plesk):
    """Checks for pre-existing email accounts before creating them"""
    domain = user[(user.find('@') + 1):]
    if plesk.exists(user):
        return ("Email user already exists.", 2)
    elif plesk.exists(domain):
        plesk.create_email(user)
        return ("User " + user + " created.", 0)
    else:
        plesk.create_domain(domain)
        plesk.create_email(user)
        return ("Domain " + dom + " did not exist. Domain and user " + user + " created.", 1)

def rsync(source, target, uname, host):
    """Synchonizes remote source folder to local target folder"""
    run = ['rsync', '-axpz', '--progress', '-e', 'ssh', uname+"@"+host+":"+source, target]
    retcode = subprocess.call(run)
    return retcode

## {{{ http://code.activestate.com/recipes/59873/ (r1)
def gen_passwd(length=8, chars=string.letters + string.digits):
    """Generates string of random characters"""
    return ''.join([random.choice(chars) for i in range(length)])

def gen_user(kind="ftp", seed=0):
    """Creates a username with a random suffix"""
    uname = kind + "_" + str(seed) + gen_passwd(3, string.digits)
    return uname

############################################
#########Begin Class definitions############
############################################

class IMAPServer(object):
    """Communicate with IMAP servers to retreive messages or upload them"""
    def __init__(self, host, user, passwd):
        try:
            self._imap = imaplib.IMAP4(host)
            try:
                resp, data = self._imap.login(user, passwd)
            except imaplib.IMAP4.error:
                raise
        except imaplib.IMAP4.error:
            raise
        return

    def list_folders(self):
        """Get a list of folders under an account"""
        resp, raw = self._imap.list()
        folders = []
        for item in raw: # One item in the raw list looks like: '(\\Unmarked \\HasChildren) "." "INBOX"'
            sp = item.split(' "." ') #Split based on the middle character, ' "." ' so we get a list ['(\\Unmarked \\HasChildren)', '"INBOX"']
            folder = sp[1][1:-1] #Take the second element (the folder name, not the flags) and then cut off the quotation marks.
            folders.append(folder) #Add the actual folder name 'INBOX' 'INBOX.Spam', etc.
        return folders

    def list_messages(self, folder):
        """List all message ID numbers inside specified folder"""
        resp, num_items = self._imap.select(folder, readonly=True)
        resp, items = self._imap.search(None, "ALL")
        items = items[0].split() #For reasons that I don't understand, imaplib returns the message IDs as a string, inside a 1-element list ['1 2 3']. This fixes that.
        return items

    def fetch_message(self, folder, id):
        """Fetch a message from a folder based on ID"""
        resp, num_items = self._imap.select(folder, readonly=True)
        resp, data = self._imap.fetch(id, '(RFC822)')
        return data[0][1] #Returns the actual message, not the list and descriptor. I hate you, IMAP.

    def add_message(self, folder, message):
        """Upload a message to specified folder"""
        resp, data = self._imap.append(folder, None, None, message)
        return data

    def subscribe(self, folder):
        """Subscribe to a folder"""
        resp, data = self._imap.subscribe(folder)
        return data

    def make_folder(self, folder):
        """Create a new IMAP folder"""
        resp, data = self._imap.create(folder)
        return data

#folders = [folder.split(' "." ')[1][1:-1] for folder in raw[1]]

    def exit(self):
        """Close IMAP connection"""
        #resp, data = self._imap.close()
        resp, data = self._imap.logout()
        return data

class UserIO(object):
    def __init__(self, access_domain=ad, primary_domain=pd, dbuser=db, dbpasswd=dbpass):
        self.emails = {}
        self.associate = ''
        self.ad = access_domain
        self.pd = primary_domain
        self.db = dbuser
        self.dbpass = dbpasswd
        return

    def _headline(self, text):
        """Highlights a section of text"""
        out = '\n'.join(['', '#' * len(text), text, '#' * len(text)])
        return out

    def welcome_banner(self):
        print self._headline('(gs) Grid-Service to (dv) Dedicated Virtual Server Migration Script v 0.1')
        print ''
        print "Before you begin, you will need to: "
        print "    a) Enable SSH access for your (gs) Grid-Service as explained in step 1 here: http://kb.mediatemple.net/questions/16/"
        print "    b) Add your (dv) Dedicated-Virtual Server's IP address to the list approved for external MySQL access, as explained here: http://kb.mediatemple.net/questions/236/"
        print ""
        print "Additionally, you will need the following information:"
        print "    1) The primary domain name and server administrator password for your (gs) Grid-Service account"
        print "    2) The access domain for your (gs) Grid-Service (this will be in the form s####.gridserver.com)"
        print "    3) If you want to move databases, the password for your primary database user (this will usually be in the form db#####)"
        print "    4) The passwords for any email accounts you wish to migrate."
        print ""
        print "Note: this script is not officially developed or supported by (mt) Media Temple. Your mileage may vary. Use at your own risk. Your (dv) Dedicated-Virtual Server is a self-managed product and you are responsible for knowing how to configure it."
        print ""
        print "When you are ready to continue, type 'yes' to proceed."
        ready = raw_input("> ")
        if ready != "yes": sys.exit("Please run this script again when you are ready.")

    def parse_config_file(self, config_file):
        try:
            self._input_dom = minidom.parse(config_file)
            #Get the primary domain
            elem_list = self._input_dom.getElementsByTagName('primary_domain')
            if len(elem_list) != 1:
                print "WARNING: Configuration syntax error. No (or multiple) 'primary_domain' sections found."
            else:
                self.pd = elem_list[0].getAttribute('value')
            #Get the access domain
            elem_list = self._input_dom.getElementsByTagName('access_domain')
            if len(elem_list) != 1:
                print "WARNING: Configuration syntax error. No (or multiple) 'access_domain' sections found."
            else:
                self.ad = elem_list[0].getAttribute('value')
            #Get the database username
            elem_list = self._input_dom.getElementsByTagName('database_user')
            if len(elem_list) != 1:
                print "WARNING: Configuration syntax error. No (or multiple) 'database_user' sections found."
            else:
                self.db = elem_list[0].getAttribute('value')
            #Get the database password
            elem_list = self._input_dom.getElementsByTagName('database_password')
            if len(elem_list) != 1:
                print "WARNING: Configuration syntax error. No (or multiple) 'database_password' sections found."
            else:
                self.dbpass = elem_list[0].getAttribute('value')
            return 0
        except IOError:
            err = "WARNING: " + config_file + " does not exist."
            self.pd, self.ad, self.db, self.dbpass = '', '', '', ''
            print err
            return 1

    def read_connection(self):
        return

    def read_emails(self):
        elem_list = self._input_dom.getElementsByTagName('associate')
        if len(elem_list) == 1:
            #Per the python docs, this returns an empty string if that attribute doesn't exist
            self.associate = elem_list[0].getAttribute('domain_name')
        else:
            self.associate = ''
        elem_list = self._input_dom.getElementsByTagName('email')
        for e in elem_list:
            username = e.getAttribute('address')
            password = e.getAttribute('password')
            self.emails[username] = password
        return emails, self.associate

    def database_prompt(self):
        self.db = raw_input("Enter your primary (gs) database username:")
        self.dbpass = getpass.getpass("Enter your (gs) database password:")
        return

    def associate_prompt(self):
        print self._headline('Select domain with which to associate @[ALL DOMAINS] addresses')
        print ''
        print 'Unlike the (gs), the (dv) does not offer @[ALL DOMAINS] addresses. You must associate these addresses with a particular domain.'
        domains = list(self.domains.migration.iterkeys())
        domains.sort()
        for d in domains:
            print d
        print ''
        associate = raw_input('Enter a domain [default: ' + self.pd + ']')
        if associate in self.domains.migration.keys():
            self.associate = associate
        else:
            self.associate = self.pd
        return


    def password_prompt(self, email):
        """Prompts the user for a password"""
        #@ALL DOMAINS addresses are stored with the access domain as the
        #hostname, because that makes sure you are logging in to the right address
        #But it would confuse the users to see that, so this replaces the access domain with [ALL DOMAINS]
        #to show the users.
        display_name = email.replace(self.ad, '[ALL DOMAINS]')
        prompt = "Enter the password for " + display_name
        print ''
        print '#' * len(prompt)
        print prompt
        print '#' * len(prompt)
        print "Type carefully, no *** will be displayed."
        print "If you prefer, you can also type 'file' to provide email passwords in a file,\nor 'skip' to skip this email user."
        new_password = getpass.getpass('Password: ')
        if new_password == 'file':
            print 'Configuration file written to gs2dv_conf.xml'
            self.write_config()
            sys.exit(0)
        elif new_password == 'skip':
            return new_password
        else:
            self.emails[email] = new_password
            return new_password
        
    def list_emails(self):
        #Replaces the access domain with [ALL DOMAINS] to display to user
        display_emails = [e.replace(self.ad, '[ALL DOMAINS]') for e in self.emails]
        #Sorts based on domain name so addresses at the same domain are grouped together.
        display_emails.sort(key=lambda e: e[e.index('@'):])
        return display_emails

    def validate_connections(self):
        while 1:
            if valid_domain(self.pd) == True:
                break
            else:
                if self.pd != '':
                    print "Error: Invalid primary domain name"                
                self.pd = raw_input('Enter your primary domain name: ')
        while 1:
            if valid_access_domain(self.ad) == True:
                break
            else:
                if self.ad != '':
                    print "Error: Invald access domain"
                self.ad = raw_input('Enter your access domain (s####.gridserver.com):')
        while 1:
            if standard_database_user(self.db):
                break
            else:
                if self.db == '':
                    print "In order to migrate databases, you must add your (dv) Dedicated-Virtual Server's IP address to the list approved for external MySQL access, as explained here: http://kb.mediatemple.net/questions/236/"
                    print "You must also enter your primary database username. If you do not want to migrate databases,\n or you don't have any database-driven sites, enter 'skip' at the prompt below."
                    db_entry = raw_input('Enter your primary database username (usually db#####):')
                else:
                    print "Are you sure that " + self.db + " is your primary database username? \n In most cases, the database username will be in the form db####."
                    print "Enter your primary database username or type 'yes' to confirm " + self.db
                    db_entry = raw_input('> ')
            if db_entry == 'yes' or db_entry == 'skip':
                break
            else:
                self.db = db_entry
        while 1:
            if self.dbpass == '':
                self.dbpass = getpass.getpass("Enter the password for your primary database user, " + self.db + "\n you will not see any *'s, so type carefully: ")
            else:
                break 
    
    def set_domains(self, domain_list):
        """Takes a dictionary of domain objects"""
        self.domains = domain_list
        
    def set_emails(self, emails):
        """Takes a dictionary of emails and passwords"""
        self.emails = emails
        return self.emails
    
    def set_databases(self, databases):
        self.databases = databases
    
    def _help_block(self, database_object):
        out = []
        for site, files in database_object.sites.iteritems():
            out.append(self._headline('For the site: http://' + site + '/'))
            out.append('')
            out.append('You will likely have to update settings in following file(s):')
            out.extend(files)
            out.append('')
            out.append('You should use these settings:')
            out.append('')
            out.append('Database host = ' + 'localhost')
            out.append('Database name = ' + database_object.new)
            out.append('Database username = ' + database_object.user)
            out.append('Database password = ' + database_object.password)
            out.append('')
        printable = '\n'.join(out)
        return printable        
    
    def write_dbhelp(self,match_dict):
        """Writes out a text file to help people update their database configuration"""
        output = ["#This file is designed to help you update the database connection settings for your sites on the (dv) Dedicated-Virtual Server.", '', "#These suggestions are based on examination of your sites' files.", "#However, you will know your site code best, and you may need to do additional configuration", '']
        for databases in match_dict.itervalues():
            for each_database in databases.itervalues():
                output.append(self._help_block(each_database))
        writeout = '\n'.join(output)
        dbhelp = open('database_configuration_help.txt', 'w')
        dbhelp.write(writeout)
        dbhelp.close()
        return
    
    def _connection_node(self):
        #Create XML node for connection variables
        connection_node = self.xml.createElement('connection')
        #Add the primary domain
        elem = self.xml.createElement('primary_domain')
        elem.setAttribute('value', self.pd)
        connection_node.appendChild(elem)
        #Add the access domain
        elem = self.xml.createElement('access_domain')
        elem.setAttribute('value', self.ad)
        connection_node.appendChild(elem)
        #Add the database user
        elem = self.xml.createElement('database_user')
        elem.setAttribute('value', self.db)
        connection_node.appendChild(elem)
        #Add the database password
        elem = self.xml.createElement('database_password')
        elem.setAttribute('value', self.dbpass)
        connection_node.appendChild(elem)
        return connection_node
    
    def _email_node(self):
        #Setup the email node    
        email_node = self.xml.createElement('emails')
        #Associate with a domain
        if self.associate:    
            associate_node = self.xml.createElement('associate')
            associate_node.setAttribute('domain_name', self.associate)
            email_node.appendChild(associate_node)
        #Write out the emails
        for e, pw in self.emails.items():
            elem = self.xml.createElement('email')
            elem.setAttribute('address', e)
            elem.setAttribute('password', pw)
            email_node.appendChild(elem)
        return email_node
    
    def _domain_node(self):
        #Setup the domain node
        domains_node = self.xml.createElement('domains')
        for domain in self.domains.migration.itervalues():
            domain_elem = self.xml.createElement('domain')
            domain_elem.setAttribute('name', domain.get_name())
            #Source
            src_node = self.xml.createElement('source')
            txt = self.xml.createTextNode(domain.source)
            src_node.appendChild(txt)
            #Target
            tgt_node = self.xml.createElement('target')
            txt = self.xml.createTextNode(domain.target)
            tgt_node.appendChild(txt)
            #Append paths to domain
            domain_elem.appendChild(src_node)
            domain_elem.appendChild(tgt_node)
            #Subdomains
            if domain.subs:                
                subdomains_node = self.xml.createElement('subdomains')
                for name, paths in domain.subs.iteritems():
                    sub_node = self.xml.createElement('subdomain')
                    sub_node.setAttribute('name', name)
                    #Source    
                    src_node = self.xml.createElement('source')
                    txt = self.xml.createTextNode(paths[0])
                    src_node.appendChild(txt)
                    #Target
                    tgt_node = self.xml.createElement('target')
                    txt = self.xml.createTextNode(paths[1])
                    tgt_node.appendChild(txt)
                    #Append paths to subdomain
                    sub_node.appendChild(src_node)
                    sub_node.appendChild(tgt_node)
                    #Add each subdomain to subdomains node
                    subdomains_node.appendChild(sub_node)
                #Append the subdomains node built above to the domain node
                domain_elem.appendChild(subdomains_node)
            #Append each domain node to the domains node.
            domains_node.appendChild(domain_elem)     
        return domains_node
    
    def _database_node(self):
        #TODO
        return

    def write_config(self):
        self.xml = minidom.Document()
        self.xml.appendChild(self.xml.createElement('gs2dv'))
        config = self.xml.documentElement
        #Connections
        connection = self._connection_node()
        config.appendChild(connection)
        #Emails
        emails = self._email_node()
        config.appendChild(emails)
        #Domains
        domains = self._domain_node()
        config.appendChild(domains)
        #Databases        
        output = self._fix_prettyxml(self.xml.toprettyxml())        
        conf_file = open('gs2dv_conf.xml', 'w')
        conf_file.write(output)
        conf_file.close()        
        return
    
    def _fix_prettyxml(self, prettyxml):
        fix = re.compile(r'((?<=>)(\n[\t]*)(?=[^<\t]))|(?<=[^>\t])(\n[\t]*)(?=<)')
        fixed = re.sub(fix, '', prettyxml)
        return fixed

# Documentation of Plesk command-line utilities used to write this class:
# http://download1.swsoft.com/Plesk/Plesk8.2/Doc/plesk-8.2-unix-cli/index.htm
class Plesk(object):
    """Allows you to interact with Plesk admin utilities"""

    # Path to Plesk utilities
    path = "/usr/local/psa/bin/"

    def __init__(self):
        self.force_configure()
        self.check_configured()
        self.get_shared_ip()
        return
    
    def cmd(self, args):
        """Run utility and get the output, error and return code in a list"""
        args[0] = self.path+args[0]
        pipe = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = pipe.communicate()
        back = list(out)
        back.append(pipe.returncode)
        return back
    
    def check_configured(self):
        """Checks if the Plesk install is configured properly"""
        self.isconfig = not(self.cmd(["init_conf", "-c"])[2])
        if self.isconfig == 0:
            print "The Plesk installation on this server is currently not configured. You will need to log in to the Plesk admin panel and complete the initial configuration, or run this script with the --force-configure option"
            sys.exit()
        return self.isconfig
    
    def get_shared_ip(self):
        """Tries to find a shared IP address, sets the first address to be shared, otherwise."""
        found = False
        output = self.cmd(["ipmanage", "-l"])[0]
        ip_list = output.splitlines()        
        del ip_list[0]  # Removes the first line which is just some junk with column descriptions
        for line in ip_list:
            if 'S' in line == True:
                self.ip = line[(line.find(":")+1):(line.find("/"))]
                found = True
                break
        if found != True:
            #Take the first line from the list of IP address, and strips out just the IP address itself.
            self.ip = ip_list[0][(ip_list[0].find(":")+1):(ip_list[0].find("/"))]
            tmp = self.cmd(['ipmanage', '-u', self.ip, '-type', 'shared'])
        return self.ip or tmp
    
    def force_configure(self):
        """Runs init_conf when called with the '--force-configure' option from the command-line"""
        for arg in sys.argv:
            if "--force-configure" in arg:
                err = self.cmd(['init_conf', '--init'])[1]
                if "Your installation is configured already." in err:
                    print "This Plesk install is configured already. Please log in to the control panel to make changes."
                    sys.exit                    
        return
      
    def create_client(self, login='gs-migration', name="(gs) Grid-Service Migration", company="Domains moved automatically from (gs)", password=0):
        """Creates a Plesk Client"""
        if password == 0:
            password = gen_passwd()            
        tmp = self.cmd(['client', '--create', \
                   login, '-name', name, \
                   '-company', company, \
                   '-passwd', password, \
                   '-notify', 'false'])
        return tmp
    
    def client_ip(self, login='gs-migration'):
        """Assigns IP address to client's IP pool"""
        tmp = self.cmd(['client_pref', '-u', login, '-ip_pool', 'add:'+ self.ip])
        return tmp
    
    def client_info(self, client):
        """Returns information about a Plesk client"""
        tmp = self.cmd(['client', '-i', client])
        return tmp
    
    def domain_info(self, domain):
        """Returns information about a Plesk domain"""
        tmp = self.cmd(['domain', '-i', domain])
        return tmp
    
    def email_info(self, email):
        """Returns information about an email address"""
        tmp = self.cmd(['mail', '-i', email])
        return tmp        
      
    def exists(self, check):
        if '@' in check:
            retcode = self.email_info(check)[2]
        elif '.' in check:
            retcode = self.domain_info(check)[2]
        else:
            retcode = self.client_info(check)[2]        
        return not retcode

    def create_domain(self, domain, client='gs-migration', ftp=0, password=0):
        """Creates a domain in Plesk"""        
        #Setting reasonable defaults for most of these. Man, there are a ton of domain options.
        #SSL options are trying to imitiate (gs) behavior.
        ip=self.ip
        if ftp == 0:
            ftp = gen_user()
        if password == 0:
            password = gen_passwd()
        tmp = self.cmd(['domain', \
                   '--create', domain, \
                   '-clogin', client, \
                   '-ip', ip, \
                   '-login', ftp, \
                   '-passwd', password, \
                   '-hosting', 'true', \
                   '-hst_type', 'phys', \
                   '-status', 'enabled', \
                   '-www', 'true', \
                   '-ssl', 'true', \
                   '-same_ssl', 'true', \
                   '-php', 'true', \
                   '-cgi', 'true', \
                   '-python', 'true', \
                   '-log_rotate', 'true', \
                   '-notify', 'false'])
        return tmp
 
    def create_subdomain(self, subdomain, domain):
        """Creates a domain in Plesk"""
        #Setting reasonable defaults for most of these. SSL options are trying to imitiate (gs) behavior.
        tmp = self.cmd(['subdomain', \
                   '--create', subdomain, \
                   '-domain', domain, \
                   '-ftp_user', 'main', \
                   '-ssl', 'true', \
                   '-same_ssl', 'true', \
                   '-php', 'true', \
                   '-cgi', 'true', \
                   '-python', 'true'])
        return tmp
    
    def set_www(self, set, domain):
        """Sets or toggles the 'www' prefix for a domain"""
        tmp = self.cmd(['domain_pref', \
                        '-u', domain, \
                        '-www', set])
        return tmp
    
    def create_db(self, domain, dbname, dbuser, passwd=0):
        if passwd == 0:
            passwd = gen_passwd()
        tmp = self.cmd(['database', \
                    '--create', dbname, \
                    '-domain', domain, \
                    '-type', 'mysql', \
                    '-add_user', dbuser, \
                    '-passwd', passwd])
        tmp.append(passwd)
        return tmp
    
    def create_email (self, emailname, passwd=0):
        if passwd == 0:
            passwd = gen_passwd()
        tmp = self.cmd(['mail', '--create', emailname, '-passwd', passwd, '-mailbox', 'true'])
        return tmp

class DomainList(object):
    """Defines a dictionary .migration containing domain objects"""
    def __init__(self, ls):
        self.migration = {}
        self.domain_count = 0
        folders = self.get_folders(ls)
        #print "DEBUG: folders is ", folders
        gs_domains = self.val_domains(folders)
        #print "DEBUG: gs_domains is ", gs_domains
        active = self.html_exists(gs_domains)
        #print "DEBUG: active is ", active
        active_minus_www = self._handle_www(active)
        #print "DEBUG: active without www is ", active_minus_www
        done = self._separate_subdomains(active_minus_www)
        return

    def get_folders(self, raw):    
        """Takes only folders"""
        folders = [x[:-1] for x in raw if x[-1] == '/'] #List comprehenshion looks for / signifier for folders.
        return folders

    def val_domains(self, folders):
        """Uses a regular expression to check for valid domains"""
        # Domain validation regex from here: http://www.shauninman.com/archive/2006/05/08/validating_domain_names
        import re
        val = re.compile(r'^([a-z0-9]([-a-z0-9]*[a-z0-9])?\.)+((a[cdefgilmnoqrstuwxz]|aero|arpa)|(b[abdefghijmnorstvwyz]|biz)|(c[acdfghiklmnorsuvxyz]|cat|com|coop)|d[ejkmoz]|(e[ceghrstu]|edu)|f[ijkmor]|(g[abdefghilmnpqrstuwy]|gov)|h[kmnrtu]|(i[delmnoqrst]|info|int)|(j[emop]|jobs)|k[eghimnprwyz]|l[abcikrstuvy]|(m[acdghklmnopqrstuvwxyz]|mil|mobi|museum)|(n[acefgilopruz]|name|net)|(om|org)|(p[aefghklmnrstwy]|pro)|qa|r[eouw]|s[abcdeghijklmnortvyz]|(t[cdfghjklmnoprtvwz]|travel)|u[agkmsyz]|v[aceginu]|w[fs]|y[etu]|z[amw])$')
        gs_domains = [x for x in folders if val.match(x.lower())] #Takes all valid domains.
        return gs_domains

    def html_exists(self, gs_domains):    
        active = [x for x in gs_domains if ssh('ls -Ad domains/'+x+'/html/*', io.pd, io.ad)[2] != 1]
        return active

    def _handle_www(self, li):  #www is a special case because some customers might have their site under www. subdomain instead of the domain name itself.
        for i in range (0, len(li)):
            if li[i][:4].lower() == 'www.':  #If any domain items start with 'www.' --made lower-case. 
                if li[i][4:] not in li: # If there's not already a domain without the www.
                    li[i] = li[i][4:] # Just strip off the www. and make it the primary domain.
                    self.migration[li[i]] = Domain(li[i], self.domain_count) #Initialize a domain object for that domain
                    self.domain_count = self.domain_count + 1
                    self.migration[li[i]].set_paths("www.") #Set the source path with the www. we removed                
        return li

    def _separate_subdomains(self, li):
        li.sort(key=len) # Sorts by length
        while li != []:
            check = "." + li.pop(0) # Takes the shortest item, and adds . to make ".foo.com" to check for matches. The . helps prevent weird matches like "foo.com.bar.com" showing as a subdomain of "foo.com"
            match = filter(lambda x: check in x, li) 
            nomatch = filter(lambda x:x not in match, li)
            li = nomatch
            for k in range (0, len(match)): # Iterate through the matching list. 
                cut_off = match[k].find(check) #Finds the index for the start of the main domain.
                match[k] = match[k][:cut_off] #Takes a slice from the start of the string up to that cutoff point, to yield just "sub1"
            if check[1:] in self.migration: #If the checked domain is already in dict from the WWW handling above...
                self.migration[check[1:]].set_subdomains(match) #Then just add the right subdomains.
            else:
                self.migration[check[1:]] = Domain(check[1:], self.domain_count) #If it's not, initialize that object
                self.domain_count = self.domain_count + 1 #Increment the number of domains
                self.migration[check[1:]].set_paths() #Set the default paths for it.
                self.migration[check[1:]].set_subdomains(match) #And add the subdomains.
        return self.migration
    
    def move(self, plesk, domain="all"):
        """Given an object of the Plesk class, moves the domains"""        
        if domain =="all":
            for i in self.migration.items():
                i[1].move(plesk)
        else:
            self.migration[domain].move()
        return
    
    def list_all(self):
        print "This script is prepared to migrate the following domains from your (gs) Grid-Service:"
        print ""
        for i in self.migration.items():
            print i[0]
            for j in i[1].get_subdomains():
                print "     " + j + '.' + i[0]
        return

    def list_domains(self):
        return self.migration.keys()
        
    def list_subdomains(self, domain):
        return self.migration[domain].get_subdomains()

class Domain(object):
    """Defines a domain object"""
    def __init__(self, name, count):
        self.name = name
        self.ftp = gen_user("ftp", count)
        return    
    
    def set_paths(self, src='', tgt=''):
        self.source = 'domains/'+ src + self.name + '/html/'
        self.target = '/var/www/vhosts/'+self.name+'/httpdocs/'
        return
    
    def get_name(self):
        return self.name
    
    def get_paths(self):
        return self.source, self.target
    
    def move(self, plesk):
        """Moves a domain and all associated subdomains"""
        if plesk.exists("gs-migration") == 0:  #If the client account doesn't, exist, create one
            plesk.create_client("gs-migration")
        set = plesk.client_ip() # Add the ip address to client's IP pool.        
        if plesk.exists(self.name) == 0:
            tmp = plesk.create_domain(self.name, "gs-migration", self.ftp) #Creates the domain name
            print "Preparing to move " + self.name
            print tmp
            tmp = kill_skel(self.target)
            tmp = rsync(self.source, self.target, io.pd, io.ad) #Actually moving the files!!!!
            tmp = rchown(self.target, self.ftp, "psacln")
            tmp = chown(self.target, self.ftp, "psaserv")
            for i in self.subs.items():
                sub = i[0]
                src = i[1][0]
                tgt = i[1][1]
                print "Preparing to move " + sub + '.' + self.name
                print "Source is: " + src
                print "Target is: " + tgt
                plesk.create_subdomain(sub, self.name)
                tmp = kill_skel(tgt)
                tmp = rsync(src, tgt, io.pd, io.ad)
                tmp = rchown(tgt, self.ftp, "psacln")
                tmp = chown(tgt, self.ftp, "psaserv")
        else:
            print self.name + " already exists on this server. Skipping migration."
        return 
        
    def set_subdomains(self, subdomains):
        self.subs = {}
        for s in subdomains:
            src = 'domains/'+s+'.'+self.name+"/html/"
            tgt = '/var/www/vhosts/'+self.name+'/subdomains/'+s+'/httpdocs/'
            self.subs[s] = (src, tgt)
        return
    
    def get_subdomains(self):
        subdomains = self.subs.keys()        
        return subdomains
    
class MySQL(object):
    def list_databases(self, access_domain, user, passwd):
        host = 'external-db.' + access_domain
        pipe = subprocess.Popen(['mysql', '-h', host, '-u', user, '-p'+passwd, '-Be', 'show databases'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        tmp = list(pipe.communicate())
        tmp.append(pipe.poll())
        if tmp[2] == 0:
            tmp[0] = tmp[0].splitlines()
            tmp[0].remove('Database')
            tmp[0].remove('information_schema')
        return tmp
        
    def dump(self, database, access_domain, user, passwd):
        host = 'external-db.' + access_domain
        pipe = subprocess.Popen(['mysqldump -h ' + host + ' -u ' + user + ' -p' + passwd + ' --add-drop-table ' + database + ' > ' + database + '.sql'], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        tmp = list(pipe.communicate())
        tmp.append(pipe.poll())
        return tmp
    
    def load(self, database, file, user, passwd, host='localhost'):
        pipe = subprocess.Popen(['mysql -h ' + host + ' -u ' + user + ' -p' + passwd + ' ' + database + ' < ' + file + '.sql'], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        tmp = list(pipe.communicate())
        tmp.append(pipe.poll())
        return tmp
    
    def copy(self, database_object, user_input):
        #Sets up the source variables. This is largely for readability.
        src_host = 'external-db.' + user_input.ad
        src_user = user_input.db
        src_pass = user_input.dbpass
        src_name = database_object.old
        #Sets up the target variables.
        tgt_host = 'localhost'
        tgt_user = database_object.user
        tgt_pass = database_object.password
        tgt_name = database_object.new
        
        print 'Copying ' + src_name + ' to ' + tgt_name + '...' 
        #Dumps from the old database and pipes into the new one.
        command = ' '.join(['mysqldump', '-h', src_host, \
                        '-u', src_user, \
                        '-p' + src_pass, \
                        src_name, \
                        '|', \
                        'mysql', '-h', tgt_host, \
                        '-u', tgt_user, \
                        '-p' + tgt_pass, \
                        tgt_name])
        retcode = subprocess.call(command, shell=True)
        if retcode == 0:
            print "Success."
        else:
            print "Failed to copy."
        return retcode
    
    def _suffixes(self, x):
        if x.endswith('.php') or x.endswith('.txt') or x.endswith('.xml') or x.endswith('.html') or x.endswith('.inc'):
            return True
        else:
            return False
        
    def match_domains(self, database_list, access_domain):
        prefix = 'db' + get_siteid(access_domain)
        #This regular expression will extract the domain name and subdomain (if found) from a file path on the dv:
        extract_names = re.compile(r'/var/www/vhosts/(?P<domain>[^/]+)/(subdomains/(?P<subdomain>[^/]+)/httpdocs|httpdocs)/')
        regex_string = '|'.join(database_list)
        all_dbs = re.compile(regex_string)
        path = '/var/www/vhosts/'        
        #Does the actual search, returns a dictionary with keys of file names and values of lines containing the DB names.
        grep_results = scriptutil.ffindgrep(path, namefs=(self._suffixes,), regexl=((regex_string, re.I)))    
        matches = {}
        count = 0
        for file, line in grep_results.iteritems():
            
            match_object = extract_names.match(file)
            domain = match_object.group('domain')
            subdomain = match_object.group('subdomain')
            if subdomain:
                site = subdomain + '.' + domain
            else:
                site = domain           
            
            db = re.search(all_dbs, line).group()
            
            if domain in matches:
                if db in matches[domain]:
                    matches[domain][db].update(site, file)
                else:
                    matches[domain][db] = Database(db, site, file, prefix, count)
                    count = count + 1
            else:
                matches[domain] = dict.fromkeys([db], Database(db, site, file, prefix, count))
                count = count + 1            
        return matches       
    
class Database(object):
    def __init__(self, name, site, file, prefix, number):
        new, user = self._new_name(name, prefix, number)
        self.old = name
        self.new = new
        self.user = user        
        self.password = gen_passwd()
        self.sites = dict.fromkeys([site], set([file]))
        return
    
    def _new_name(self, old, prefix, count=0):    
        clean = old.replace(prefix + '_', '')
        name = 'gs%02d_%s' % (count, clean)
        new  = (name[:64], name[:16])
        return new
    
    def update(self, site, file):
        if site in self.sites:
            self.sites[site].add(file)
        else:
            self.sites[site] = set([file])


def main():


    io = UserIO()
    io.welcome_banner()
    io.parse_config_file('gs2dv_conf.xml')
    io.read_connection()
    io.validate_connections()
    psa = Plesk()

    print "Testing connections..."

    if ssh_works(io.pd, io.ad) == False:
        set = setup_keys(io.pd, io.ad)
        if set[2] == 1:
            print ''
            print '#' * 39
            print "Error: " + set[1]
            print "Unable to connect to (gs) Grid-Service."
            print '#' * 39
            print "Are you sure that SSH access is enabled? Are you entering the correct password?"
            print "For details, see http://kb.mediatemple.net/questions/16"
            print "Exiting..."
            sys.exit(1)
        # Removes duplicate keys inserted from multiple runs of this script.
        ssh('sort ~/.ssh/authorized_keys | uniq > ~/.ssh/tmp && mv ~/.ssh/tmp ~/.ssh/authorized_keys', io.pd, io.ad)

    DB = MySQL()
    while 1:
        tmp = DB.list_databases(io.ad, io.db, io.dbpass)
        if tmp[2] != 0:
            try:
                tmp[1].index('error: 1045')
                print "Error: unable to log in to database server with username/password provided."
                io.database_prompt()
            except ValueError:
                try:
                    tmp[1].index('error: 2003')
                    print "Error: unable to connect to database server."
                    print "Make sure you add " + io.ip + " to the list of allowed external IP addresses"
                    print "For details, please see: http://kb.mediatemple.net/questions/236/"
                    sys.exit(1)
                except ValueError:
                    sys.exit("Unknown database error: " + tmp[1])               
        else:
            break
    io.set_databases(tmp[0])

    print "Gathering information from (gs) Grid-Service... (this may take a few minutes)"
    all = get_list(io.pd, io.ad)
    d = DomainList(all)
    emails = get_emails(io.pd, io.ad)

    io.set_domains(d)
    io.set_emails(emails)

    io.domains.list_all()
        
    go = raw_input('Type "yes" to continue: ')
    if go != "yes":
        sys.exit('Run this script again when you are ready.')

    io.domains.move(psa)   

    print "\nThis script is ready to migrate emails for the following addresses:"
    for i in io.list_emails():
        print i
    go = raw_input("Type 'yes' to continue or 'skip all' to skip email migration: ")
    if go != "yes" and go != 'skip all':
        sys.exit('Run this script again when you are ready.')

    if go != 'skip all':
        if not io.associate:
            io.associate_prompt()
        for address, password in emails.items():
            if password == "ENTER PASSWORD HERE" or password == '':
                password = io.password_prompt(address)
                fail_count = 0
                while fail_count < 3 and password != 'skip':
                    try:
                        source = IMAPServer(io.ad, address, password)                    
                        psa.create_email(address.replace(io.ad, io.associate), password)
                        target = IMAPServer(psa.ip, address.replace(io.ad, io.associate), password)
                        migrate_email(source, target)
                        source.exit()
                        target.exit()
                        break
                    except imaplib.IMAP4.error:
                        print 'Error: Unable to connect to (gs) Grid-Service email server.'
                        password = io.password_prompt(address)
                        fail_count = fail_count + 1
                else:
                    print 'Skipping ' + address
                    print 'You must move this address manually.'

    if io.databases == []:
        print "Migration complete."
        sys.exit(0)
    else:
        print '\nThe script is prepared to migrate the following databases:\n'
        for db in io.databases:
            print db
        go = raw_input('Type "yes" to continue: ')
        if go != "yes":
            sys.exit('Run this script again when you are ready.')
        match = DB.match_domains(io.databases, io.ad)
        for domain, databases in match.iteritems():
            for db_object in databases.itervalues():
                psa.create_db(domain, db_object.new, db_object.user, db_object.password)
                DB.copy(db_object, io)
        io.write_dbhelp(match)
        print "Migration complete."
        print "You may need to update your database connection scripts to work on the new (dv)"
        print "For assistance, please see the 'database_configuration_help.txt' file created by this script."


if __name__ == '__main__':
    main()
