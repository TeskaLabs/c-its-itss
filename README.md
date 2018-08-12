# C-ITS ITS-S Reference Implementation

This is a reference implementation of the ITS-S (a client side) as defined in ETSI C-ITS standards.
Its main purpose is to enable implementators of the ITS-S software to study and validate their implementations from a security perspective.
The server side (Enrollment Authority, Authorization Authority and Certification Authority) is provided by TeskaLabs' SeaCat CA.
It also contains a simple [ITS-G5](https://en.wikipedia.org/wiki/IEEE_802.11p) network simulator that utilizes UDP IPv4 multicast.

Cooperative Intelligent Transport Systems (C-ITS) allow road users and traffic managers to share information and use it to coordinate their actions.
It is a set of standards that describes data exchange between high-speed vehicles and between the vehicles and the roadside infrastructure, so called V2X communication.

## Quick start

 1. Ensure that you have Python 3.5, 3.6 or 3.7 installed.  
    Please referrer to a documentation of your OS or to a Python official documentation how to install Python.
    We assume, that your python interpretter is available as `python3` binary.  
    Supported OS are: Linux, Windows, Mac OSX.
    
 2. [Ensure](https://pip.pypa.io/en/stable/installing/) that you have pip, the python installer.
 
 3. Install dependencies
 
         pip3 install -U asn1tools
         pip3 install -U cryptography
         pip3 install -U requests
 
 4. Clone the repository
 
         git clone https://github.com/TeskaLabs/c-its-itss.git

## Usage

         $ ./itss.py --help
         usage: itss.py [-h] [-e EA_URL] [-a AA_URL] [--g5-sim G5_SIM] DIR
         
         C-ITS ITS-S reference implementation focused on a security.
         C-ITS standards: ETSI TS 102 941 v1.1.1, ETSI TS 103 097 v1.2.1
         It also contains a simple ITS-G5 network simulator that utilizes UDP IPv4 multicast.
         
         (C) 2018 TeskaLabs

         positional arguments:
           DIR                   A directory with persistent storage of a keying
                                 material
         
         optional arguments:
           -h, --help            show this help message and exit
           -e EA_URL, --ea-url EA_URL
                                 URL of the Enrollment Authority
           -a AA_URL, --aa-url AA_URL
                                 URL of the Authorization Authority
           --g5-sim G5_SIM       Configuration of G5 simulator


## C-ITS standards

  * ETSI TS 102 941 v1.1.1
  * ETSI TS 103 097 v1.2.1
  
  
