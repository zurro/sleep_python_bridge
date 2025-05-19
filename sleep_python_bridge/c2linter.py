#!/usr/local/bin/python3

# The idea for this tool and some code came from redshell: https://github.com/Verizon/redshell

# This tool will connect to a cobalt strike team server to perform various tasks such as payload generation, hosting files, and other fun tasks

# It can also be imported like a library to be used by other tools. 
# If used as a library, the items won't be printed to the console, as this is done in the Main function

import asyncio, re



### Start CSConnector Class ###
class C2lint:
    def __init__(self, cs_directory="./"):

        self.cs_directory = cs_directory
        # NOTE: Leverage c2lint
        self.c2lintcmd = f'./c2lint'
        self.ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        self.summary_pattern = re.compile(r".*Detected \d+ (?:warnings|errors).*",re.IGNORECASE)
        # This gets populated once the connect function is run (in the future, maybe run that function in the initialization?)

    async def run_c2lint(self, profile_path, sleep_time: int = 0):
        full_cmd = [self.c2lintcmd, profile_path]
        result = await self.run_command(full_cmd)
        await asyncio.sleep(sleep_time)
        return await self.parse_c2lint_output(result)
    
    async def parse_c2lint_output(self, output):
        output = self.ansi_escape.sub('', output)
        lines = output.splitlines()

        warnings = []
        errors = []
        passed = []
        full_output = output 

        for line in lines:
            stripped = line.strip()
            if stripped.startswith("[+]"):
                passed.append(stripped[4:])
            elif stripped.startswith("[!]") and not re.match(self.summary_pattern, line):
                warnings.append(stripped[4:])
            elif stripped.startswith("[x]") and not re.match(self.summary_pattern, line):
                errors.append(stripped[4:])

        return {
            "passed": passed,
            "warnings": warnings,
            "errors": errors,
            "full_output": full_output
        }
    
    async def run_command(self, command):
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=f"{self.cs_directory}/server"
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 1:
            print("Error:", stderr.decode())
            raise RuntimeError(f"Command {command} failed with code {process.returncode}")
        return stdout.decode()

### End CSConnector Class ###

##### Main ########

def parseArguments():
    parser = ArgumentParser()

    parser.add_argument("-p", "--profile", help="profile path", required=True)
    parser.add_argument("-d", "--csdir", help="the path to the directory containing the Cobalt Strike JAR file", default="./")

    args = parser.parse_args()
    return args


async def main():
    args = parseArguments()

    cs_profile_linter = C2lint(args.csdir)
    print(await cs_profile_linter.run_c2lint(args.profile))


if __name__ == '__main__':
    # There are some imports which aren't used when this is a library, so they are imported here instead
    from argparse import ArgumentParser
    from os import environ

    asyncio.run(main())