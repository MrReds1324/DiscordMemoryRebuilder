# DiscordMemoryRebuilder

Install the required python packages with
``` pip install -r requirements.txt```

Put the set of message files you want to use to rebuild a chat into a directory. Each message file should be post-pended with the uid each person wishes to use to register to the server with.
i.e
```
messages_bob.csv
messages_123.csv
messages_bobert.csv
```
Then run the message_merger.py script pointing the input to the directory containing these message files. This will build a combined message csv file and containing all messages and which uid they should be sent to. This also generates a list of uids that the server will be listening for.

The next step is to run the server using the generated messages.csv and config. Note: you will need to port forward port 8080 if you are on your home network.

When the server starts up it will give you the public IP address that other users will need to connect to with their clients.

Clients will use clients.py with their uid and the public IP of the server, and once all clients have connected then messages will be sent to each client to write into discord. Note: You must be tabbed into the chat/channel you wish your messages to be posted.