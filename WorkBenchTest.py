import time
from tenable.io import TenableIO
tio = TenableIO('xxxxxxxxxxxxxxxxxxx', 'xxxxxxxxxxxxxx')
print (time.asctime())
with open('example.nessus', 'wb') as exportobj:
    tio.workbenches.export(fobj=exportobj, plugin_id=19506)
    print (time.asctime())