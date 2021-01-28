import requests
import hashlib
import sys
def request_api_data(query_data):
    url = 'https://api.pwnedpasswords.com/range/' + query_data
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError('The problem is: {}, check the API'.format(res.status_code))
    return res

def get_password_leaks(hashes, hash_to_count): #hashes is response
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h,count in hashes:
        if h == hash_to_count:
            return count
    return 0

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char , rest = sha1password[0:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks(response,rest) #respone = the first 5 char from input

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print('\'{}\' was found {} times, maybe you have to change your password.'.format(password,count))
        else:
            print('Password was NOT found!')

if __name__ == '__main__':
    main(sys.argv[1:])

