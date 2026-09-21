import subprocess

def execute_show_stdout(cmd):
    """ Prints out each new line of output (from STDOUT) from the subprocess. """
    popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
    for line in popen.stdout: print(line.decode(), end='')
    popen.stdout.close()
    return_code = popen.wait()
    if return_code:
        raise subprocess.CalledProcessError(return_code, cmd)