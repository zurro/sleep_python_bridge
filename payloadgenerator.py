#!/usr/local/bin/python3
import os
from sleep_python_bridge.striker import ArtifactType, CSConnector

from argparse import ArgumentParser
from pprint import pp, pprint
from pathlib import Path, PurePath
import json
import time
import glob
import asyncio
####################
## Variables

# hostPayload
hostPayload = False

# JSON file
datafile = "payloads.json"

# payloadpath
script_dir = Path(__file__).resolve().parent
payloadPath = script_dir / "output" / "payloads"
os.makedirs(payloadPath, exist_ok=True)


####################
## FUNCTIONS
def parseArguments():
    global payloadPath

    parser = ArgumentParser()
    parser.add_argument('host', help='The teamserver host.')
    parser.add_argument('port', help='The teamserver port.')
    parser.add_argument('username', help='The desired username.')
    parser.add_argument('password', help='The teamserver password.')
    parser.add_argument('path', help="Directory to CobaltStrike")

    opt = parser.add_argument_group('optional parameters')
    opt.add_argument('-o', '--payload-path', metavar='path', default=payloadPath, help=f"Where to save generated payloads. Default: {payloadPath}")
    opt.add_argument('-l', '--listener', metavar='name', default='all', help=f"Specify listener name to get payloads for. Default: payloads for all listeners will be produced")
    opt.add_argument('-a', '--arch', metavar='arch', default='both', choices=['both', 'x64', 'x86'], help=f"Specify payload architecture. Choices: x86, x64. Default: payloads for both are generated")
    opt.add_argument('-t', '--payload-types', metavar='types', default='exe,dll,bin', help=f"Comma separated list of payload types to generate keyed by file extensions. Choices: exe,dll,svc.exe,bin,ps1,py,vbs or use 'all' to compile all at once. Default: exe,dll,bin")
    opt.add_argument('-e', '--exit', metavar='exit', choices=['thread', 'process'], default='process', help=f"Payload exit method. Choices: thread, process. Default: process")
    opt.add_argument('-c', '--call-method', metavar='method', choices=['direct', 'indirect', 'none', ''], default='', help=f"System call method. Choices: indirect, direct, none. Default: <empty> (backwards compatible with Cobalt pre 4.8)")

    args = parser.parse_args()

    payloadPath = args.payload_path

    return args


async def write_payload(payloadPath,payloadName,payloadBytes,hostPayload=hostPayload):

    filename = PurePath(payloadPath,payloadName)
    with open(filename, 'wb') as file:
        file.write(payloadBytes)

async def main(args):

    cs_host = args.host
    cs_port = args.port
    cs_user = args.username
    cs_pass = args.password
    cs_directory = args.path
    cs_listener = args.listener
    cs_exit = args.exit
    cs_callmethod = args.call_method.capitalize()
    cs_types = args.payload_types
    cs_architectures = [args.arch, ]

    if cs_callmethod == '':
        cs_exit = ''

    if args.arch == 'both':
        cs_architectures = ['x86', 'x64']

    ####################
    ## Connect to server
    print(f"[*] Connecting to teamserver: {cs_host}")
    async with CSConnector(
        cs_host=cs_host, 
        cs_port=cs_port, 
        cs_user=cs_user, 
        cs_pass=cs_pass,
        cs_directory=cs_directory) as cs:

        # Load external scripts (if desired)
        print("Loading cna scripts from ./payload_scripts")
        for script in glob.glob("./payload_scripts/*.cna"):
            await cs.ag_load_script(Path(script).resolve())

        #time.sleep(3) # Allow time for the scripts to load
        # Output the loaded scripts
        loadedScripts = await cs.ag_ls_scripts()
        print(loadedScripts)

        payloadTypes = {
            'dll' : ArtifactType.DLL,
            'exe' : ArtifactType.EXE,
            'svc.exe' : ArtifactType.SVCEXE,
            'bin' : ArtifactType.RAW,
            'ps1' : ArtifactType.POWERSHELL,
            'py' : ArtifactType.PYTHON,
            'vbs' : ArtifactType.VBSCRIPT,
        }

        if cs_types == 'all':
            cs_types = ','.join(payloadTypes.keys())

        payloads = [x for x in cs_types.split(',') if x in payloadTypes]

        # Generate the payloads for each listener
        listeners = await cs.get_listeners_stageless()
        for listener in listeners:
            if cs_listener != 'all' and listener.lower() != cs_listener.lower():
                continue

            print(f"[*] Creating stageless payloads for listener: {listener}")

            for arch in cs_architectures:
                for k in payloads:
                    payloadName = f'{listener}.{arch}.{k}'
                    print(f"[*] Creating {payloadName}")
                    payloadBytes = await cs.generatePayload(listener, payloadTypes[k], False, arch == 'x64', cs_exit, cs_callmethod)
                    await write_payload(payloadPath, payloadName, payloadBytes, hostPayload)

    #########

if __name__ == "__main__":
    print("------------------------")
    print("Beacon Payload Generator")
    print("------------------------")
    args = parseArguments()
    asyncio.run(main(args))