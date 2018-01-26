# meltdown-aws-scanner #
Naive shell script to verify Meltdown (CVE-2017-5754) patch status of EC2 instances

# Requirements #
* aws cli with working configuration

# Using the script #
## Scan all EC2 instances in default account and region ##
    $ ./check_meltdown.sh | tee $(date '+%Y-%m-%d').csv
## Scan a subset of EC2 instances in default account and region ##
    $ ./check_meltdown.sh --filters "Name=tag:Name,Values=prod-*"
