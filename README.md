## Contact

**Utkarsh Shukla**

Email- utqrshkumar07@gmail.com

GitHub- https://github.com/Utkarshshukla4


##  Overview
This project monitors IoT network traffic to detect intrusions or suspicious behavior using Python-based anomaly detection models.  
It can run on Raspberry Pi, Windows, or Linux.



##  Features
- Behavior-based intrusion detection  
- Works on multiple platforms  
- Logs suspicious device activities  
- CLI interface  



##  Architecture

[IoT Network Traffic]
      ↓
[Packet Capture (scapy / tshark)]
      ↓
[Feature Extraction]
      ↓
[Anomaly Detection Model]
      ↓
[Alert / Log Generation]



## Project Structure

iot-network-ids/
├── src/
├── dataset/
├── docs/
│   └── architecture.png
├── requirements.txt
├── README.md
└── .gitignore


## Installation


git clone https://github.com/<your-username>/IoT_Network_IDS.git

cd IoT_Network_IDS



 ## Create virtual environment

_Windows_

python -m venv env

env\Scripts\activate

pip install -r requirements.txt 

_Linux_

python3 -m venv env

source env/bin/activate

python3 -m pip install -r requirements.txt 

## Run

_Windows_

python ids_monitor_crossplatform.py


_Linux_

sudo python3 ids_monitor_crossplatform.py


## Input Example

The tool automatically captures packets from connected devices.

## Output Example

Device: ESP8266  
Activity: Normal  
Anomaly Score: 0.02

 ## Summary

This IDS monitors IoT traffic and alerts about suspicious behaviors to protect network integrity.
