# Private Set Intersection for Threat Intelligence Sharing

 This repository contains a simple implementation of **Private Set Intersection (PSI)** using real-world cyber threat intelligence data.

The project demonstrates how two parties can identify shared Indicators of Compromise (IOCs) without revealing their complete datasets to one another.

The datasets used in this project originate from [abuse.ch ThreatFox](https://threatfox.abuse.ch/).

The PSI implementation is written in **C** using the [libsodium cryptographic library](https://libsodium.org/).


## Overview

Threat intelligence sharing is important for improving cyber defence and identifying malicious infrastructure. However, organisations are often unwilling to share raw IOC datasets due to privacy, operational, and security concerns.

Private Set Intersection (PSI) provides a privacy-preserving solution that allows two parties to compute the intersection of their datasets without exposing non-matching entries.

This repository simulates that scenario using IOC datasets split between two parties:

- Alice
- Bob


## Technologies Used

- C
- Python
- [libsodium](https://libsodium.org/)
- CSV/TXT datasets


## Dataset

The original IOC dataset was obtained from:

- [ThreatFox by abuse.ch](https://threatfox.abuse.ch/)

The preprocessing scripts clean and extract IOC values such as:

- Domains
- IP addresses
- URLs
- File hashes

The cleaned dataset is then split into separate datasets representing two organisations participating in PSI.


## PSI Scenario

This project simulates a threat intelligence sharing environment where:

- Alice possesses one IOC dataset
- Bob possesses another IOC dataset

Using Private Set Intersection, both parties can identify overlapping malicious indicators without exposing their full threat intelligence feeds.


## Running the Project

### Compile

```bash
gcc psi.c -lsodium -o psi
```

### Run

```bash
./psi
```


## Preprocessing Workflow

The Python scripts are used to prepare the dataset before PSI execution.

### Cleaning the Dataset

```bash
python3 clean_dataset.py
```

### Splitting the Dataset

```bash
python3 split_dataset.py
```

This generates:

- `alice_dataset.txt`
- `bob_dataset.txt`


## Purpose

This repository was created for educational and research purposes related to:

- Private Set Intersection (PSI)
- Privacy-preserving computation
- Cyber threat intelligence sharing
- Cybersecurity research


## References

- [abuse.ch ThreatFox](https://threatfox.abuse.ch/)
- [libsodium Documentation](https://doc.libsodium.org/)
- [Private Set Intersection – Wikipedia](https://en.wikipedia.org/wiki/Private_set_intersection)
