#!/usr/bin/env python3

import argparse
from concurrent.futures import ThreadPoolExecutor
import functools
import os
import sys
from urllib.parse import urlparse

import eapi

__version__ = "0.1.11"

def is_valid_file(arg):
    """Checks if a arg is an actual file"""
    if not os.path.exists(arg):
        msg = "{0} is not a file or it does not exist".format(arg)
        raise argparse.ArgumentTypeError(msg)
    else:
        return arg

def parse_args():
    parser = argparse.ArgumentParser(
        epilog="Example: python3 copyimage.py -f switches.txt")
    parser.add_argument("-f", "--filename", required=True,
                        help="input file with ip address", metavar="FILE",
                        type=is_valid_file)
    parser.add_argument("-i", "--image", required=True, help="Specify image to boot")
    parser.add_argument("-u", "--username", type=str, default="admin",
                        help="Specify username to be used to login to the switches")
    parser.add_argument("-p", "--password", type=str, default="",
                        help="Specify password to be used to login to the switches")
    parser.add_argument("-l", "--limit", type=int, default=10,
                        help="Limit concurrent copies")
    parser.add_argument("-t", "--transport", type=str, default="http")
    parser.add_argument("--verify-ssl-cert", type=str, default="true")
    parser.add_argument("--timeout", type=int, default=300)

    args = parser.parse_args()
    return args

def get_switch_ips(filename):
    with open(filename) as f:
        lines = [line.strip() for line in f]
    return lines

def image_loaded(sess, name, md5=None):
    response = sess.send(["bash timeout 30 [ -e /mnt/flash/{} ]; echo $?".format(name)], encoding="text")
    
    return True if int(response[0].output.strip()) == 0 else False

def _worker(switch, args):
    try:
        sess = eapi.Session(switch, auth=(args.username, args.password), transport=args.transport, verify=args.verify_ssl_cert, timeout=args.timeout)

        hostaddr = sess.hostaddr

        if not image_loaded(sess, args.image):
            print("%s: Image '%s' is not loaded" % (hostaddr, args.image))
            return

        response = sess.send(["configure", "boot system flash:%s" % args.image])
        
        if "errors" in response[1]:
            print("%s: An error occured: %s" % (hostaddr, response[1]["errors"][0]))
            return
        
        print("%s: Successfully set '%s' to boot on next reload" % (hostaddr, args.image))
    
    except OSError as exc:
        print("%s: %s" % (hostaddr, exc.strerror))
    except Exception as exc:
        print("%s: %s" % (hostaddr, str(exc)))
def main():

    args = parse_args()
    switches = get_switch_ips(args.filename)

    if args.verify_ssl_cert == "false":
        args.verify_ssl_cert = False
        eapi.SSL_WARNINGS = False
    elif args.verify_ssl_cert == "true" or not args.verify_ssl_cert:
        # default behavior
        args.verify_ssl_cert = True
    else:
        # hopefully it's a valid path to a certificate
        pass

    with ThreadPoolExecutor(max_workers=args.limit) as executor:
        part = functools.partial(_worker, args=args)
        for _ in executor.map(part, switches):
            pass
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)