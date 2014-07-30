#! /usr/bin/env python
# 
#  mailsync.py
#
#  Copy mails from one mailbox to another. Checks mail IDs to avoid duplicates.
#
#  Copyright (c) 2014 Andriy Vitushynskyy.   
#  License : GPL2
# 
__author__ = "vitush"

import sys
import re
import imaplib
import hashlib
import socket
import email.parser
from datetime import date, timedelta
import ConfigParser

CHUNK_SIZE = 100
# IMAP responses should normally begin 'OK' - we strip that off
def check_response(resp):
    status, value = resp
    if status !='OK':
        sys.stderr.write("Error: got '%s' response: " % status)
    return value

list_response_pattern = re.compile(r'\((?P<flags>.*?)\) "(?P<delimiter>.*)" (?P<name>.*)')

def parse_list_response(line):
    flags, delimiter, mailbox_name = list_response_pattern.match(line).groups()
    mailbox_name = mailbox_name.strip('"')
    return (flags, delimiter, mailbox_name)

#Increase imap search limit from _MAXLINE = 10000 to 100000
_MAXLINE = 100000
def readline_fixed(self):
    """Read line from remote."""
    line = self.file.readline(_MAXLINE + 1)
    if len(line) > _MAXLINE:
        raise self.error("got more than %d bytes" % _MAXLINE)
    return line


def get_arguments():

    from optparse import OptionParser
    parser = OptionParser(usage="%prog options ")
    parser.add_option("-f","--config",    dest='config_file',      help='Config File ')
    parser.add_option("-s","--src-server",dest='src_server',help='Source IMAP server')
    parser.add_option("-S","--dst-server",dest='dst_server',help='Destination IMAP server')
    parser.add_option("-p","--src-port",  dest='src_port',  help='Source IMAP server port', type='int')
    parser.add_option("-P","--dst-port",  dest='dst_port',  help='Destination IMAP server port', type='int')
    parser.add_option("-u","--src-user",  dest='src_user',  help='Source IMAP user')
    parser.add_option("-U","--dst-user",  dest='dst_user',  help='Destination IMAP user')
    parser.add_option("-w","--src-password",  dest='src_password',  help='Source IMAP password',type="string")
    parser.add_option("-W","--dst-password",  dest='dst_password',  help='Destination IMAP password',type="string")
    parser.add_option("-x", "--src-ssl",   dest='src_ssl',   action="store_true", help='Use SSL')
    parser.add_option("-X", "--dst-ssl",   dest='dst_ssl',   action="store_true", help='Use SSL')
    parser.add_option("-d","--start-date", dest='start_date',help='Start from date YYYYMMDD ')
    parser.add_option("-D","--end-date"  , dest='end_date',  help='End date YYYYMMDD')
    parser.add_option("-v", "--verbose",   dest="verbose",   action="store_true", help="Verbose mode")
    parser.add_option("-c", "--checksum", dest="use_checksum", action="store_true", 
                        help="Use a checksum of several mail headers, instead of the Message-ID")
    parser.add_option("-m", "--checksum-with-id", dest="use_id_in_checksum", action="store_true", 
                        help="Include the Message-ID (if any) in the -c checksum.")
    parser.add_option("-l", "--list", dest="just_list", action="store_true", 
                                            help="Just list mailboxes on Source Server")

    parser.set_defaults(verbose=False, ssl=False, dry_run=False, just_list=False,src_port=143,dst_port=143)
    (options, args) = parser.parse_args()
  
    config = ConfigParser.ConfigParser()    
    #Load Data from config file
    if options.config_file:
        config.read(options.config_file)
        for a in config.items("IMAPCopy"):
            setattr(options, a[0],a[1])
              
    if (not options.start_date) or (not options.end_date):
            sys.stderr.write("\nError: Must specify Start and End dates. \n")
            parser.print_help()
            sys.exit(1)
         
    
    if options.just_list:
        if (not options.src_server) or (not options.src_user) :
            sys.stderr.write("\nError: Must specify src-server, src-users, src-passwords.\n")
            parser.print_help()
            sys.exit(1)
    else:
        if (not options.src_server) or (not options.dst_server) or (not options.src_user) or (not options.dst_user):
            sys.stderr.write("\nError: Must specify servers, users, passwords .\n\n")
            parser.print_help()
            sys.exit(1)


    return (options, args)

def connect_imap_server(server,port,user,password,ssl=False):
    
    if ssl:
        serverclass = imaplib.IMAP4_SSL
    else:
        serverclass = imaplib.IMAP4

    # Use a another function with increased limits
    serverclass.readline=readline_fixed

    # Connect to Server 
    try:
        if port != 143 :
            srv = serverclass(server, port)
        else:
            srv = serverclass(server)
    except socket.error as e:
        sys.stderr.write("\nFailed to connect to server ({0}:{1}).\n".format(server,port))
        sys.stderr.write("%s\n\n" % e)
        sys.exit(1)
        
    if ('STARTTLS' in srv.capabilities) and hasattr(srv, 'starttls'):
        srv.starttls()
    elif not ssl:
        sys.stderr.write('\nWarning: Not encrypted connection to Server {0} \n'.format(server))

    try:
        srv.login(user, password)
    except:
        sys.stderr.write("\nError: Login failed to Server {0}\n".format(server))
        sys.exit(1)
    
    return srv

def get_message_id(parsed_message, 
                   options_use_checksum = False, 
                   options_use_id_in_checksum = False):
    """
    If user specified, use md5 hash of several headers as message id.
    

    For more safety, user should first do a dry run, reviewing them before deletion. 
    Problems are extremely unlikely, but md5 is not collision-free.

    Otherwise use the Message-ID header. Print a warning if the Message-ID header does not exist.
    """
    if options_use_checksum:
        md5 = hashlib.md5()
        md5.update(("From:"    + parsed_message['From']).encode('utf-8'))
        md5.update(("To:"      + parsed_message['To']).encode('utf-8'))
        md5.update(("Subject:" + parsed_message['Subject']).encode('utf-8'))
        md5.update(("Date:"    + parsed_message['Date']).encode('utf-8'))
        md5.update(("Cc:"      + parsed_message.get('Cc','')).encode('utf-8'))
        md5.update(("Bcc:"     + parsed_message.get('Bcc','')).encode('utf-8'))
        if options_use_id_in_checksum:
            md5.update(("Message-ID:"    + parsed_message.get("Message-ID","")).encode('utf-8'))
        msg_id = md5.hexdigest()
        print(msg_id)
    else:
        msg_id = parsed_message['Message-ID']
        if not msg_id:
            print("Message '%s' dated '%s' has no Message-ID header." % (
                parsed_message['Subject'], parsed_message['Date']))
            print("You might want to use the -c option.")
            return None
    return msg_id

def print_message_info(parsed_message):
    print("From: " +    parsed_message.get('From',''))
    print("To: " +      parsed_message.get('To',''))
    print("Cc: " +      parsed_message.get('Cc',''))
    print("Bcc: " +     parsed_message.get('Bcc',''))
    print("Subject: " + parsed_message.get('Subject',''))
    print("Date: " +    parsed_message.get('Date',''))
    print("")

def get_messages_ids(p,server,imap_filter,options,date=None):
    
    date_str = ""
    if date is not None:
        date_str = date
        
    msg_ids = {} 
    if options.verbose: 
        print ("%s    Reading the mails ids ... (in batches of %d)" % (date_str,CHUNK_SIZE))
    
    msgnums = check_response(server.search(None, imap_filter))[0].split()
    for i in range(0, len(msgnums), CHUNK_SIZE):
        msgnums_in_chunk = msgnums[i:i + CHUNK_SIZE]
        message_ids = ','.join(msgnums_in_chunk)
        # Get the header of each message
        ms = check_response(server.fetch(message_ids, '(RFC822.HEADER)'))
        if options.verbose:
            print ("%s      Batch starting at item %d" % (date_str,i))
                        
        for ci in range(0, len(msgnums_in_chunk)):
            mnum = msgnums_in_chunk[ci]
            mp = p.parsestr(ms[ci * 2][1])
            msg_id = get_message_id(mp, options.use_checksum, options.use_id_in_checksum)

            if msg_id:
                msg_ids[msg_id] = mnum
    return msg_ids

def copy_emails(p,date,src_server,dst_server,mbox,options):

    copied_num = 0  
    imap_filter='(SENTON "{0}")'.format(date)

    src_msgs_ids = get_messages_ids(p,src_server,imap_filter,options,date)
    dst_msgs_ids = get_messages_ids(p,dst_server,imap_filter,options,date)

    msgnums_tocopy = []
    #Exclude messages that are already there, and do not to be copied again. 
    for msg_id in src_msgs_ids.keys():
        if msg_id not in dst_msgs_ids.keys():
            msgnums_tocopy.append(src_msgs_ids[msg_id])
    
    msg2copy = len(msgnums_tocopy)
    if options.verbose: 
        src_msgnums = check_response(src_server.search(None, imap_filter))[0].split()
        print ("%s -> %s of %s mails need to be copied" % (date,msg2copy,len(src_msgnums)))

    for i in range(0, msg2copy, CHUNK_SIZE):
        if options.verbose:
            print ("%s    Batch starting at item %d" % (date,i))

        msgnums_in_chunk = msgnums_tocopy[i:i + CHUNK_SIZE]
        message_ids = ','.join(msgnums_in_chunk)
        # Get mails
        ms = check_response(src_server.fetch(message_ids, '(RFC822)'))
        # Copy each mails.
        for ci in range(0, len(msgnums_in_chunk)):
            mnum = msgnums_in_chunk[ci]
            if options.verbose:
                prc = int( (100*(i+ci) ) / msg2copy )
                print("%s     Coping %s message %s (%s %%)" % (date,mbox, mnum, prc ))
            dst_server.append(mbox, None, None, ms[ci*2][1])
            copied_num = copied_num + 1   
            
    return copied_num
        
def main():
    options, args = get_arguments()

    start_date = date(int(options.start_date[0:4]),int(options.start_date[4:6]),int(options.start_date[6:8]))
    end_date = date(int(options.end_date[0:4]),int(options.end_date[4:6]),int(options.end_date[6:8]))
    one_day = timedelta(days=1)

    src_server = connect_imap_server(options.src_server, options.src_port, options.src_user, options.src_password, options.src_ssl)
    dst_server = connect_imap_server(options.dst_server, options.dst_port, options.dst_user, options.dst_password, options.dst_ssl)

    # List mailboxes option
    if options.just_list:
        for mb in check_response(src_server.list()):
            mb = mb.decode('utf-7')
            bits = parse_list_response(mb)
            if r'\\Noselect' not in bits[0]:
                print(bits[2])
        sys.exit()
         
    if len(args) == 0:
        sys.stderr.write("\nError: Must specify mailbox\n")
        sys.exit(1)

    if options.verbose:
        print("Coping mails from {0}@{1}:{2} to {3}@{4}:{5}".format(
            options.src_user,
            options.src_server,
            options.src_port,
            options.dst_user,
            options.dst_server,
            options.dst_port))
 
    copied_sum = 0
    try:
        p = email.parser.Parser()
        for mbox in args:
            
            src_msgs = check_response(src_server.select(mbox))[0]
            dst_msgs = check_response(dst_server.select(mbox))[0]
            if options.verbose:
                print("There are %d messages in SRC %s in total." % (int(src_msgs),mbox))
                print("There are %d messages in DST %s in total." % (int(dst_msgs),mbox))
                                       
            date1 = start_date
            while date1 <= end_date:
                if options.verbose:
                    print("-------------------------------")
                date_str = date1.strftime('%d-%b-%Y') 
                copied_num = copy_emails(p,date_str,src_server,dst_server,mbox,options)
                copied_sum = copied_sum + copied_num        
                date1 = date1 + one_day

        print("Copied %s messages." % (copied_sum))
                    
        src_server.close()
        dst_server.close()
    finally:
        src_server.logout()
        dst_server.logout()
        
if __name__ == '__main__':
    main()