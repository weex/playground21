#.!/usr/bin/env python3

import sys, json, os, argparse

# import from the 21 Developer Library
from two1.commands.config import Config
from two1.lib.wallet import Wallet
from two1.lib.bitrequests import BitTransferRequests

# set up bitrequest client for BitTransfer requests
wallet = Wallet()
username = Config().username
requests = BitTransferRequests(wallet, username)

# server address
def buy(args):
    primary_address = wallet.get_payout_address()
    sel_url = "{0}buy?address={1}&contact={2}"
    answer = requests.get(url=sel_url.format(args.url, primary_address, args.contact))
    if answer.status_code != 200:
        print("Could not make offchain payment. Please check that you have sufficient balance.")
    else:
        print(answer.text)

# store and read back a piece of data, reporting failure if it didn't work
# also create a directory of those files and store that as a file, writing it to a text file
def sync(args):
    '''Uploads and checks files we want stored on a single causeway server'''
    # read through a directory of files and store each one under a random hash, save hashes+filenames
    # to a local sqlite db.
                 
    # check if we have a local db and if not create it
    con = sqlite3.connect('local.db')
    con.execute("create table files (filename text primary key, filehash text)")
    con.execute("create table placement (id integer primary key, filename text, url text, \
                                    remote_filename text, verified integer)")

    check = []
    upload = []
    listing = glob.glob(os.path.join(args.path, "*.json"))
    for l in listing:  
        # check if file is in local key db
        row = con.execute("select * from files where filename = ?", (l,))
        filehash = hashlib.sha256(open(l, 'r').read()).hexdigest()
        if row is None:
            con.execute("insert into files (filename, filehash) VALUES (?, ?)", (l,filehash))
            # for new files, we'll upload them
            upload.append({'name': l})
        else:
            # for existing files, download and verify them
            check.append(('name':row['filename'], 'filehash':row['filehash']})

    # now that we know what we need to check and upload let's do the checking first, any that 
    # come back wrong can be added to the upload queue.
    # download each value (later a hash only with some full downloads for verification)
    for f in check:
        value = open(f['name'], 'r')
        data = value.read()
        value.close()
        if len(data) > 8192:
            raise ValueError('File is too big. 8192 bytes should be enough for anyone.')
        else:
            # handle changes on our side, to update or replace local files?
            row = con.execute("select * from placement inner join files on files.filename = placement.filename\
                                    where placement.filename = ?", (f['name']))
            if row is None:
                upload.append({'name': l})
            else:
                for r in row:
                    # download value, hash and check its hash
                    remote_name = row['remote_filename']
                    sel_url = "{0}get?key={1}"
                    answer = requests.get(url=sel_url.format(args.url, remote_filename))
                    filehash = hashlib.sha256(answer.text).hexdigest()
                    if status_code == 404: 
                        # log not found error, add to upload
                    elif filehash != r['filehash']:
                        # log wrong error, add to upload
                    else:
                        #update verified
                    # cases we need to handle, doesn't exist, exists but wrong, correct

    failed = []
    for f in upload:
        value = open(f['name'], 'r')
        data = value.read()
        value.close()

        if len(data) > 8192:
            raise ValueError('File is too big. 8192 bytes should be enough for anyone.')
        else:
            a = ''
            setattr(a, 'key', remote_name)
            setattr(a, 'value', data)
            setattr(a, 'nonce', args.nonce)
            res = json.loads(put(args))
            if 'result' not in res or res['result'] != 'success':
                # houston we have a problem
                failed.append(f['name'])
    
    for f in upload:
        row = con.execute("select * from placement where filename = ?", (l,))
        if row is None:
            upload.append({'name': l})
            con.execute("insert into placement (filename, url) values (?, ?)", (l, args.url))

                remote_filename = ''.join(random.SystemRandom().choice(string.ascii_uppercase \
                                        + string.digits) for _ in range(32)))
                row2 = con.execute("insert into placement (filename, url, remote_filename) \
                                        values (?, ?, ?)", (f['name'], args.url, remote_filename,))

    # if not, generate its hash and create a local record
    # for each placement of the file, we generate a random name for it and create a 'placement' record for it
    #   which includes the proposed url to place it. 
    # then place the file
    # after placement, retrieve it and update the verified time

def put(args):
    primary_address = wallet.get_payout_address()
    message = args.key + args.value + primary_address + args.nonce
    signature = wallet.sign_message(message)

    data = {"key": args.key, 
            "value": args.value,
            "nonce": args.nonce,
            "signature": signature,
            "address": primary_address}

    sel_url = "{0}put"
    body = json.dumps(data)
    headers = {'Content-Type': 'application/json'}
    answer = requests.post(url=sel_url.format(args.url), headers=headers, data=body)
    print(answer.text)

def delete(args):
    primary_address = wallet.get_payout_address()
    message = args.key + primary_address + args.nonce
    signature = wallet.sign_message(message)

    data = {"key": args.key, 
            "nonce": args.nonce,
            "signature": signature,
            "address": primary_address}
    sel_url = "{0}delete"
    body = json.dumps(data)
    headers = {'Content-Type': 'application/json'}
    answer = requests.post(url=sel_url.format(args.url), headers=headers, data=body)
    print(answer.text)

def get(args):
    sel_url = "{0}get?key={1}"
    answer = requests.get(url=sel_url.format(args.url, args.key))
    print(answer.text)

def buy_file(server_url = 'http://localhost:5000/'):

    # get the file listing from the server
    response = requests.get(url=server_url+'files')
    file_list = json.loads(response.text)

    # print the file list to the console
    for file in range(len(file_list)):
        print("{}. {}\t{}".format(file+1, file_list[str(file+1)][0], file_list[str(file+1)][1]))

    try:
        # prompt the user to input the index number of the file to be purchased
        sel = input("Please enter the index of the file that you would like to purchase:")

        # check if the input index is valid key in file_list dict
        if sel in file_list:
            print('You selected {} in our database'.format(file_list[sel][0]))

            #create a 402 request with the server payout address
            sel_url = server_url+'buy?selection={0}&payout_address={1}'
            answer = requests.get(url=sel_url.format(int(sel), wallet.get_payout_address()), stream=True)
            if answer.status_code != 200:
                print("Could not make an offchain payment. Please check that you have sufficient balance.")
            else:
                # open a file with the same name as the file being purchased and stream the data into it.
                filename = file_list[str(sel)][0]
                with open(filename,'wb') as fd:
                    for chunk in answer.iter_content(4096):
                        fd.write(chunk)
                fd.close()
                print('Congratulations, you just purchased a file for bitcoin!')
        else:
            print("That is an invalid selection.")

    except ValueError:
        print("That is an invalid input. Only numerical inputs are accepted.")

def nonce(args):
    primary_address = wallet.get_payout_address()
    sel_url = args.url + 'nonce?address={0}'
    answer = requests.get(url=sel_url.format(primary_address))
    print(answer.text)

def address(args):
    primary_address = wallet.get_payout_address()
    sel_url = args.url + 'address?contact={0}&address={1}&signature={2}'
    answer = requests.get(url=sel_url.format(args.contact, primary_address, args.signature))
    print(answer.text)

def help(args):
    print("Please run with --help")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Interact with Causeway server")
    #parser.set_defaults(func=help)
    subparsers = parser.add_subparsers(help="Commands")

    parser_buy = subparsers.add_parser('buy', help="Purchase hosting bucket")
    parser_buy.add_argument('url', help='Url of the Causeway server with trailing slash.')  
    #parser_buy.add_argument('address', help='Address used as username for the service.')  
    parser_buy.add_argument('contact', help='Email address to contact on expiration.')  
    parser_buy.set_defaults(func=buy)

    parser_put = subparsers.add_parser('put', help="Set or update a value for a key")
    parser_put.add_argument('url', help='Url of the Causeway server with trailing slash.')  
    #parser_put.add_argument('address', help='Address used as username for the service.')  
    parser_put.add_argument('key', help='Data storage key')  
    parser_put.add_argument('value', help='Data stored by key')  
    parser_put.add_argument('nonce', help='Nonce for signature uniqueness.')  
    parser_put.set_defaults(func=put)

    parser_delete = subparsers.add_parser('delete', help="Delete a key/value pair.")
    parser_delete.add_argument('url', help='Url of the Causeway server with trailing slash.')  
    #parser_delete.add_argument('address', help='Address used as username for the service.')  
    parser_delete.add_argument('key', help='Data storage key')  
    parser_delete.add_argument('nonce', help='Nonce for signature uniqueness.')  
    parser_delete.set_defaults(func=delete)

    parser_get = subparsers.add_parser('get', help="Download the value stored with a key")
    parser_get.add_argument('url', help='Url of the Causeway server with trailing slash.')  
    parser_get.add_argument('key', help='Key to retrieve')  
    parser_get.set_defaults(func=get)

    parser_nonce = subparsers.add_parser('nonce', help="Get nonce for the address")
    parser_nonce.add_argument('url', help='Url of the Causeway server with trailing slash.')  
    #parser_nonce.add_argument('address', help='Address used as username for the service.')  
    parser_nonce.set_defaults(func=nonce)

    parser_address = subparsers.add_parser('address', help="Get a deposit address")
    parser_address.add_argument('url', help='Url of the Causeway server with trailing slash.')  
    parser_address.add_argument('contact', help='Email address to contact on expiration.')  
    parser_address.add_argument('address', help='Address used as username for the service.')  
    parser_address.add_argument('signature', help='Signature of "contact,address" using address\' privkey') 
    parser_address.set_defaults(func=address)
   
    args = parser.parse_args()
    args.func(args)
