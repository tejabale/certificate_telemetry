# Certificate Telemetry

This repository contains scripts to collect TLS information from a list of IPs and save the output as a CSV file.

## Step by Step Process

1. Clone the repository:

    ```bash
    git clone https://github.com/tejabale/certificate_telemetry.git
    cd certificate_telemetry
    ```

2. Copy the file `input.txt`, containing the list of IPs, into the `myfiles` folder within the `certificate_telemetry` directory. Sample input examples are provided in the `myfiles` folder.
                  ![sample input](screenshots/Screenshot1.png)

4. Run the following command to collect TLS information using `zgrab2` and `jq`, and save the output as JSON:

    ```bash
    cat myfiles/sample_input.txt | ./zgrab2 http -p 443 --use-https | jq -c  'select(.data.http.result.response.request.tls_log != null) | {ip: .ip, tls_log: .data.http.result.response.request.tls_log}' > myfiles/sample_output.json
    ```
      ![](screenshots/Screenshot2.png)
5. Navigate to the `myfiles` directory:

    ```bash
    cd myfiles
    ```

6. Execute the Python script `cert.py` with the input JSON file and desired output CSV file:

    ```bash
    python3 cert.py -i sample_output.json -o sample_output.csv
    ```

    Here, the `-i` argument specifies the input JSON file, and `-o` specifies the output CSV file.
   
     ![](screenshots/Screenshot3.png)
8. The output data is saved into the `sample_output.csv` file in the `myfiles` folder.

**NOTE:** 
- Make sure to replace sample_input.txt and sample_output.json with your actual input and output filenames if they differ. Additionally, ensure that jq are properly installed and available in your environment.

# Zgrab2

Zgrab2 is a fast, versatile network scanner designed for efficient security auditing and network monitoring. It can perform various types of scans including grabbing certificates from domains and IP addresses. 

## Installation

Detailed instructions for installing Zgrab2 can be found in the official GitHub repository: [zmap/zgrab2](https://github.com/zmap/zgrab2)

To install Zgrab2, follow these steps:

```bash
$ git clone https://github.com/zmap/zgrab2.git
$ cd zgrab2
$ go build
$ make
$ ./zgrab2

