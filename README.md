# SSL-stripping including secure cookie stripping

To install all the needed modules go the installation guide.

To run the tool, go to the tools location and open a terminal at that location.
In the terminal type:

> sudo python main.py

Now the program is running and the stripping can start.

The tool will then ask:

> What is the victim IP address?

Here you enter the IP address of the victim you want to poison/attack.
Make sure that this victim IP address is on the same network as you are, else the poisoning will not work.

The tool will then ask:

> What is the gateway IP address?

Here you need the enter the gateway's IP address of your network.
This can be found by using ifconfig in a terminal and looking at the ip address after broadcast.

Lastly the tool will ask:

>What is your network interface?

Here you need to give the network interface you are currently connected to via the internet, this can also be found by using the ifconfig command in a terminal and looking at which network interface you are currently using (typically of type: eth0, enp0s3 or enp0s8).

After this, whenever the victim connects to a website using http you can read information about their requests in the terminal.
