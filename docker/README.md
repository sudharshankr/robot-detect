## Step 1 - Build the erlang server image
`git clone https://github.com/jonathanraes/erlang-tlsserver`

`cd erlang-server && docker build -t erlang-server .`

## Step 2 Option 1 - Use a pcap file

### Install requirements
`pip install -r requirements.txt`

### Run erlang server
`docker run --publish 4000:4000 --name erlang-server erlang-server`

### Run pcap attack
`python attack.py ../capture.pcapng`

## Step 2 option 2 - Run interactive attack

### Build attack image
`docker build -t robotattack .`

### Run interactive attack
`docker-compose up`