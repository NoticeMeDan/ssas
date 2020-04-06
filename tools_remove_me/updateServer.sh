#!/bin/bash
rsync -rp ./* ssas@192.168.56.101:/home/ssas/html
ssh -t ssas@192.168.56.101 "sudo cp -rp /home/ssas/html/* /var/www/html/ && rm -r /home/ssas/html"