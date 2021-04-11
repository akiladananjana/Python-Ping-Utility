# Python-Ping-Utility
Ping Utility Implementation using Python

# Basic Info 
This is the basic implementation of the ping utility using Python. In this program I create a ICMP packets and send them to relevant destination. 
I changed the ICMP packet's type to 8 for indicate ICMP echo-request. Then the destination machine reply with ICMP code 0 that indicates echo-reply. 
I capture that ICMP echo-reply packet and prints the ping is success.

# Usage

I developed this tool using Ubuntu 20.04 VM with Python 3.8.2 and also recommended to use that version. Fire up the terminal, navigate to ping utility directory 
and execute the following command:</br></br>
``` python3 python_ping.py 8.8.8.8 ens33 ``` </br>
</br>
8.8.8.8 : Destination IP</br>
ens33 : Interface name that needs to be source for ICMP messages</br>

## Following table has various ICMP types
| ICMP Type     | Literal                                                          |
| :------------ |:---------------------------------------------------------------: | 
| 0             | echo-reply                                                       |
| 3             | destination unreachable code 0 = net unreachable 1 = host unreachable 2 = protocol unreachable 3 = port unreachable 4 = fragmentation needed and DF set 5 = source route failed                                                                |
| 4             | source-quencht                                                   |
| 5             | redirect code 0 = redirect datagrams for the network 1 = redirect datagrams for the host 2 = redirect datagrams for the type of service and network 3 = redirect datagrams for the type of service and host                                |
| 6             | alternate-address                                                |
| 8             | echo-request                                                     |
| 9             | router-advertisement                                             |
| 10            | router-solicitation                                              |
| 11            | time-exceeded code 0 = time to live exceeded in transit 1 = fragment reassembly time exceeded   |
| 12            | parameter-problem                                                |
| 13            | timestamp-request                                                |
| 14            | timestamp-reply                                                  |
| 15            | information-request                                              |
| 16            | information-reply                                                |
| 17            | mask-request                                                     |
| 18            | mask-reply                                                       |
| 31            | conversion-error                                                 |
| 32            | mobile-redirect                                                  |


# Required Packages
* netifaces : To read the NIC information.
