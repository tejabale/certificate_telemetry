# Certificate Telemetry

This repository contains scripts to collect TLS information from a list of IPs and save the output as a CSV file.

## Step by Step Process

1. Clone the repository:

    ```bash
    git clone https://github.com/tejabale/certificate_telemetry.git
    cd certificate_telemetry
    ```

2. Copy the file `input.txt`, containing the list of IPs, into the `myfiles` folder within the `certificate_telemetry` directory. Sample input examples are provided in the `myfiles` folder.

3. Run the following command to collect TLS information using `zgrab2` and `jq`, and save the output as JSON:

    ```bash
    cat myfiles/sample_input.txt | ./zgrab2 http -p 443 --use-https | jq -c  'select(.data.http.result.response.request.tls_log != null) | {ip: .ip, tls_log: .data.http.result.response.request.tls_log}' > myfiles/sample_output.json
    ```

4. Navigate to the `myfiles` directory:

    ```bash
    cd myfiles
    ```

5. Execute the Python script `cert.py` with the input JSON file and desired output CSV file:

    ```bash
    python3 cert.py -i sample_output.json -o sample_output.csv
    ```

    Here, the `-i` argument specifies the input JSON file, and `-o` specifies the output CSV file.

6. The output data is saved into the `sample_output.csv` file in the `myfiles` folder.
