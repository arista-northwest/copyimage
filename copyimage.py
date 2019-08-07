#!/usr/bin/env python3
import sys
import argparse
import os
import ssl

import eapi

import functools
import asyncio
import warnings
from urllib.parse import urlparse
#warnings.filterwarnings("ignore")


def is_valid_file(arg):
    """Checks if a arg is an actual file"""
    if not os.path.exists(arg):
        msg = "{0} is not a file or it does not exist".format(arg)
        raise argparse.ArgumentTypeError(msg)
    else:
        return arg

def parse_args():
    parser = argparse.ArgumentParser(
        epilog="Example: python3 copyimage.py -f switches.txt -i http://path.to/image.swi -r management -s /path/to/image.swi.sha512sum")
    parser.add_argument("-f", "--filename", required=True,
                        help="input file with ip address", metavar="FILE",
                        type=is_valid_file)
    parser.add_argument("-u", "--username", type=str, default="admin",
                        help="Specify username to be used to login to the switches")
    parser.add_argument("-p", "--password", type=str, default="",
                        help="Specify password to be used to login to the switches")
    parser.add_argument("-i", "--image", type=str, required=True,
                        help="Specify image, with path, to be copied to the switches")
    parser.add_argument("-n", "--name", type=str,
                        help="Specify image name to be specified on the switch")
    parser.add_argument("-s", "--sha512", type=str, required=True,
                        help="Specify sha512 filename for the image")
    parser.add_argument("-r", "--vrf", default="default", type=str)

    args = parser.parse_args()
    return args

def get_switch_ips(filename):
    with open(filename) as f:
        lines = [line.strip() for line in f]
    return lines

def get_sha512(filename):
    with open(filename) as f:
        lines = [line.split(" ")[0].strip() for line in f]
    return lines[0]

def progress(filename, size, sent):
    sys.stdout.write("%s\'s progress: %.2f%%   \r" % (filename, float(sent)/float(size)*100) )

def image_loaded(sess, name, md5=None):
    response = sess.send(["bash timeout 30 [ -e /mnt/flash/{} ]; echo $?".format(name)], encoding="text")
    
    return True if int(response[0].output.strip()) == 0 else False

async def _aloader(switches, args):
    loop = asyncio.get_event_loop()

    tasks = []
    def _blocking(sess, args):

        hostaddr = sess.hostaddr
        
        if not image_loaded(sess, args.name):
            print("{}: {} is not present on flash. Copying...".format(hostaddr, args.name))
            response = sess.send([
                "enable",
                "routing-context vrf {}".format(args.vrf),
                "copy {} flash:/{}".format(args.image, args.name)
            ], encoding="json")
        else:
            print("{}: {} is present on flash. Skipping...".format(hostaddr, args.name))

        if not image_loaded(sess, args.name):
            print("{}: Image is still not present. Something went wrong".format(hostaddr))
            #sys.exit(0)

        #Verify Copy
        response = sess.send(["verify /sha512 flash:{}".format(args.name)], encoding="text")
        sha512 = str(response[0]).strip().split(" ")[-1]

        if get_sha512(args.sha512) == sha512:
            print("{}: SHA512 check passed. Copy Verified.".format(hostaddr))
        else:
            print("{}: SHA512 check failed. Image may be corrupted.".format(hostaddr))
            # sess.send(["delete flash:{}".format(args.name)])
    
    for switch in switches:
        sess = eapi.Session(switch, auth=(args.username, args.password))
        part = functools.partial(_blocking, sess, args)
        tasks.append(loop.run_in_executor(None, part))
    
    completed, _ = await asyncio.wait(tasks)

    return [task.result() for task in completed]
    
def main():

    args = parse_args()
    switches = get_switch_ips(args.filename)

    if not args.name:
        args.name = os.path.basename(urlparse(args.image).path)

    loop = asyncio.get_event_loop()
    responses = []
    for response in loop.run_until_complete(_aloader(switches, args)):
        responses.append(response)

    return responses

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
