import subprocess
import re
import multiprocessing
import sys
import os
from tqdm import tqdm

RE = re.compile(r'(ip:(?:[0-9]{1,3}\.){3}[0-9]{1,3})')

def run_once(p):
    try:
        out, err = subprocess.Popen(['python', './main.py', p], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate(timeout=60*10)
    except subprocess.TimeoutExpired:
        # print(f'{p}: Timeout!')
        return
    except subprocess.CalledProcessError:
        # print(f'{p} : error : {err.decode("utf-8")}')
        return

    out = out.decode('utf-8').replace(' ', '')
    ip = RE.findall(out)

    return (p, ip[0] if len(ip) > 0 else '')

folder = './Second-Stage'
script = []
for a, b, c in os.walk(folder):
    if len(b) == 0:
        script += list(map(lambda x: os.path.join(a, x), c))

with open('result.csv', 'w') as rf:
    with multiprocessing.Pool(os.cpu_count()) as pool:
        for res in tqdm(pool.imap(run_once, script), total=len(script)):
            if res:
                rf.write(f'{os.path.basename(res[0])}, {res[1]}\n')
                rf.flush()