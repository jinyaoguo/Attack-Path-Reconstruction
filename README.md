# Attack Analysis System Based on Syslog

## Introduction

This project is based on system logs and alarm information to conduct trace analysis of received attacks. Given the log files and alarm events as input, it can automatically generate attack chain diagrams and attack entry point information for further analysis by security personnel. This project refers to the idea of Fang et al. [1], and after reproducing it, optimizations were made in the attack path recognition and weight normalization parts.

Architecture：

* `src`：source code

* `input` : log file to be processed

* `output` output of the model

  

## Run

1. Set up the Python 3 environment and install the dependencies.

   ```shell
   pip install graphviz
   pip install numpy
   pip install scikit-learn
   ```

2. Switch to the `src` folder and run the program.
   
   ```shell
   cd src
   python main.py -n crackhost2 -l ../input/crackhost2.log -e /tmp/john/password_crack.txt -r /tmp/john/password_crack.txt -o ../output -s 124
   ```



## Input：

In the `input` folder, there is a sample input file named `crackhost2.log`, which records both normal system log behavior and password theft attacks over a period of time. The attack chain is illustrated in the following diagram:

<img src="imgs\crackhost2.png" alt="crackhost2" style="zoom:80%;" />

Entry Point of the attack：`192.168.29.207:55150->192.168.29.145:22`

PoI (point of interest) event：`/home/maicha/normal.txt`



## Output：

* `_path` save the identified attack path 
* `Final.dot` final compressed attack subgraph
* `BackTrack.dot` dependency graph after back-propagation



## Reference

[1] Fang P, Gao P, Liu C, et al. {Back-Propagating} System Dependency Impact for Attack Investigation[C]//31st USENIX Security Symposium (USENIX Security 22). 2022: 2461-2478.

