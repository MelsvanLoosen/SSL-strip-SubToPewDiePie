# SSL-stripping including secure cookie stripping

To install all the needed modules go the installation guide.

To run the tool, go to the tools location and open a terminal at that location.
In the terminal type:

> sudo python main.py

Now the programming is running and the stripping can start.

The tool will then ask you to enter the victims IP address, make sure that the victim you want to poison/attack is on the same network as you are, else the poisoning will not work.
Then the tool will ask for the getaway router’s ip address, this can be found by using ifconfig in a terminal and looking at the ip address after broadcast.
Lastly the tool will ask you to define your own network interface, this can also be found by using the ifconfig command in a terminal and looking at which network interface you are currently using (typically of type: eth0, enp0s3 or enp0s8).
