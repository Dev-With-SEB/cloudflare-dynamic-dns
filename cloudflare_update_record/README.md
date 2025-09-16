# cloudflare_update_record.py

Updates a DNS A or AAAA record on Cloudflare with the system's current external IPv4/v6 address.

It obtains the external IPv4/v6 address from a *provider* (default: https://icanhazip.com), sets it for a specified record and finally writes it to a file to check with next time.

Originally writen by va1entin
    va1entin's [Repo]https://github.com/va1entin/tools/tree/master/cloudflare_update_record
    va1entin's [blog post](https://valh.io/p/python-script-for-cloudflare-dns-record-updates-dyndns/) for more information and config instructions.


## Get usage

```bash
cloudflare_update_record.py -h
```

## Update a DNS A record

```bash
cloudflare_update_record.py -4
```

## Update a DNS AAAA record

```bash
cloudflare_update_record.py -6
```

## Config format

```yaml
read_token: "<YOUR READ TOKEN>"
edit_token: "<YOUR EDIT TOKEN>"
zone_name: "<YOUR ZONE NAME>"
record_name: "<YOUR RECORD NAME>" # use "@" for root record
```

### Or

if you have multiple records

```yaml
read_token: "<YOUR READ TOKEN>"
edit_token: "<YOUR EDIT TOKEN>"
zone_name: "<YOUR ZONE NAME>"
record_name:
    - "<YOUR RECORD NAME>" # use "@" for root record    record_name: 
    - "<YOUR 2nd RECORD NAME>"
```

### Or

if you have multiple Zones & Records

```yaml
zones:
    - zone_name: "<YOUR 1st ZONE NAME>"
        read_token: "<YOUR READ TOKEN>"
        edit_token: "<YOUR EDIT TOKEN>"
        record_name:
            - "<YOUR RECORD NAME>" # use "@" for root record    record_name: 
            - "<YOUR 2nd RECORD NAME>"

    - zone_name: "<YOUR 2nd ZONE NAME>"
        read_token: "<YOUR 2nd ZONE READ TOKEN>"
        edit_token: "<YOUR 2nd ZONE EDIT TOKEN>"
        record_name:
            - "<YOUR 2nd ZONE RECORD NAME>" # use "@" for root record    record_name: 
            - "<YOUR 2nd ZONE 2nd RECORD NAME>"        
```    