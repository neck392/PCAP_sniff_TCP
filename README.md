# PCAP_sniff_TCP
> WHS

Sniffing the source and destination ports of TCP packets.

## Caution
You must change the NIC corresponding to your computer.<br>
You can check the NIC name using the __ifconfig__ or __ip a__ command.
```C
    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);  // Change "ens33"
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }
```

## How to run
```bash
$git clone https://github.com/neck392/PCAP_sniff_TCP.git
$cd PCAP_sniff_TCP
$gcc -o pcap pcap.c -lpcap
$sudo ./pcap
```
