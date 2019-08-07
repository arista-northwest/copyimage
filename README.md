# copyimage

Copy EOS images to many switches

## Usage
usage: copyimage.py [-h] -f FILE [-u USERNAME] [-p PASSWORD] -i IMAGE
                    [-n NAME] -s SHA512 [-r VRF]

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --filename FILE
                        input file with ip address
  -u USERNAME, --username USERNAME
                        Specify username to be used to login to the switches
  -p PASSWORD, --password PASSWORD
                        Specify password to be used to login to the switches
  -i IMAGE, --image IMAGE
                        Specify image, with path, to be copied to the switches
  -n NAME, --name NAME  Specify image name to be specified on the switch
  -s SHA512, --sha512 SHA512
                        Specify sha512 filename for the image
  -r VRF, --vrf VRF

## Example

python3 copyimage.py -f switches.txt -u admin -p admin -i http://path.to/image.swi -r management -s /path.to/image.swi.sha512sum