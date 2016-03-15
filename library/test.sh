#!/bin/bash

../ansible/hacking/test-module -m sdapi.py -a "junosspace_host=junosspace1.kdc.jnpr.net device=labsrx source_zone=lab junosspace_password=juniper123 change_request_id=cr100 services=http destination_zone=jnpr junosspace_username=super source_addresses=100.100.100.100 destination_addresses=200.200.200.200"

echo "done"
