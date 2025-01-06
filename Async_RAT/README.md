# AsyncRAT Spammer

This script is designed to spam an AsyncRAT controller application with fake client connections. 
Each simulated client sends random data, including payloads filled with random Chinese characters, to overwhelm the controller and potentially crash it.

## Features

- Spawns multiple fake clients to connect to an AsyncRAT controller.
- Sends random payloads filled with large amounts of random Chinese characters.
- Designed to stress test the AsyncRAT controller application.

## Usage

python script_name.py -ip 127.0.0.1 -port 7707 -threads 50



