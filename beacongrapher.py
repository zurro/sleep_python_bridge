#!/usr/local/bin/python3
from sleep_python_bridge.striker import CSConnector

from argparse import ArgumentParser
from pprint import pp, pprint
from pathlib import Path
import json
import asyncio
import os

####################
## Variables
# Initialize lists
beaconsresult = [] # raw data from CS
beaconLogs = [] # Cleaned list to feed final JSON

# JSON file
datafile = "beacons.json"

####################
## FUNCTIONS
def parseArguments():
    parser = ArgumentParser()
    parser.add_argument('host', help='The teamserver host.')
    parser.add_argument('port', help='The teamserver port.')
    parser.add_argument('username', help='The desired username.')
    parser.add_argument('password', help='The teamserver password.')
    parser.add_argument('path', help="Directory to CobaltStrike")
    
    args = parser.parse_args()
    return args

def convert_java_to_python(obj):
    if isinstance(obj, dict):
        return {convert_java_to_python(k): convert_java_to_python(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_java_to_python(item) for item in obj]
    elif hasattr(obj, '__int__') and type(obj).__name__ == 'JavaInt':
        return int(obj)
    else:
        return obj

async def main(args):

    cs_host = args.host
    cs_port = args.port
    cs_user = args.username
    cs_pass = args.password
    cs_directory = args.path

    ####################
    ## Connect to server
    print(f"[*] Connecting to teamserver: {cs_host}")
    async with CSConnector(
        cs_host=cs_host, 
        cs_port=cs_port, 
        cs_user=cs_user, 
        cs_pass=cs_pass,
        cs_directory=cs_directory) as cs:

        beacons = await cs.get_beacons()

        print("[*] Getting beacon logs from teamserver...")
        beaconsresult = beacons
    ####################
    ## Process Logs

    # JSON field reference: type, beacon_id, user, command, result, timestamp

    if beaconsresult is None:
        print("[!] No logs yet. Did you just start the teamserver?")
        exit()

    links = []

    # Add Node Icons
    for beacon in beaconsresult:
        print(beacon)

        nodeIcon = u'\uf0e7'

        if beacon["pbid"] == "":
            nodeIcon = u'\uf0e7'

        else:
            nodeIcon = u'\uf0e7'
        
        beacon.update({"nodeIcon":nodeIcon})
        beacon.update({"build":str(beacon["build"])})

    # Create Links
    for beacon in beaconsresult:
        beacon_source = beacon["id"]
        beacon_target = ""
        beacon_type = ""

        if beacon["phint"] == "":
            beacon_type = "HTTP"
            beacon_target = "0" # teamserver
        elif beacon["phint"] == "445":
            beacon_type = "SMB"
            beacon_target = beacon["pbid"]
        else:
            beacon_type = "TCP"
            beacon_target = beacon["pbid"]
            
        
        # Add each beacon to list
        links.append({"source":beacon_source,"target":beacon_target,"type":beacon_type})

    # Add teamserver reference
    beaconsresult.append({
        'alive': 'true',
        'arch': '',
        'barch': '',
        'build': '0',
        'charset': '',
        'computer': '',
        'external': '',
        'host': 'teamserver',
        'id': '',
        'internal': '',
        'is64': '',
        'last': '',
        'lastf': '',
        'listener': '',
        'nodeIcon': '\uf0e7',
        'note': '',
        'os': 'Cobalt Strike',
        'pbid': '',
        'phint': '0',
        'pid': 'teamserver',
        'port': '',
        'process': 'teamserver',
        'session': '',
        'user': 'admin',
        'ver': 'teamserver',
        "nodeIcon":u'\uf233'
        })
    pprint(beaconsresult)
    pprint(links)

    output = json.dumps({"nodes":convert_java_to_python(beaconsresult),"links":convert_java_to_python(links)},ensure_ascii=False).encode('utf-8')
    #print(output)
    script_dir = Path(__file__).resolve().parent
    datapath = script_dir / "output" / "html" / "data"
    os.makedirs(datapath, exist_ok=True)
    with open(f'{str(datapath)}/beacons.json', 'wb') as the_file:
        the_file.write(output)

if __name__ == "__main__":
    args = parseArguments()
    asyncio.run(main(args))