# nessiberas
CLI tool for managing multiple Nessus reports.

Uses argparse.

# Basic usage
python nessiberas mode pathToDirectoryWithNessusFiles options (options)

# Examples
Check all vulnerable hosts from all reports in folder ./reports (plugin 10028) and lists them as protocol:hostip:port

```
minmaxer@prellermbp:~/nessiberas$ python nessiberas.py pluginid 10028
udp:192.168.220.129:53
udp:192.168.11.165:53
```