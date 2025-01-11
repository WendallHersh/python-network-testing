# **Deep Network Explorer**  
A powerful and versatile Python-based tool designed to scan your local network for active devices and inspect open ports for selected hosts. The program combines network discovery, reverse DNS lookup, and categorized port scanning to give you detailed insights into your network.

---

## **Features**  
- **Network Discovery**: Identify all active devices in your local network along with their IP addresses and hostnames.  
- **Reverse DNS Lookup**: Automatically resolve hostnames for detected devices.  
- **Port Scanning**:  
  - Scan predefined categories of ports (e.g., Web Services, SSH, Database Services).  
  - Scan all ports across all categories.  
- **Cross-Platform Compatibility**: Supports Windows, macOS, and Linux.  
- **User-Friendly Interface**: Simple menu-driven interaction to guide users through network scanning and port scanning.

---

## **Prerequisites**  
1. **Python**: Ensure Python 3.8 or later is installed on your system.  
2. **Permissions**: Run the program with appropriate permissions to access network interfaces.

---

## **Installation**  
1. Clone this repository or download the script file:  
   ```
   git clone https://github.com/your-username/deep-network-explorer.git  
   cd deep-network-explorer  
   ```  
2. Install required dependencies (if any):  
   ```
   pip install -r requirements.txt  
   ```

---

## **Usage**  
Run the program in your terminal using Python:  
```
python deep_network_explorer.py  
```  

**Steps:**  
1. **Network Discovery**: The program identifies all active devices in the local network and displays their IP addresses and hostnames.  
2. **Device Selection**: Select a device from the displayed list to perform a port scan.  
3. **Port Scanning**:  
   - Choose a predefined category of ports to scan (e.g., Web Services, IoT).  
   - Scan all available ports across categories.  
4. **Results**: View detailed results of the port scan, including whether each port is open or closed.

---

## **Example Output**  
### **Network Discovery**  
```
Starting Deep Network Explorer...  
Local IP: 192.168.1.101  
Gateway: 192.168.1.1  
Subnet Mask: 255.255.255.0  

Scanning the network for active devices...  
Active device found: 192.168.1.102 (Johns-PC)  
Active device found: 192.168.1.103 (Printer-Office)  
Active device found: 192.168.1.105 (Smart-Thermostat)  

Active Devices Found:  
1. 192.168.1.102 (Johns-PC)  
2. 192.168.1.103 (Printer-Office)  
3. 192.168.1.105 (Smart-Thermostat)  
```

### **Port Scanning**  
```
Enter the number of a device to scan ports, or press Enter to exit: 2  

Available Port Categories:  
1. Web Services  
2. SSH and Remote Access  
3. Email Services  
4. File Sharing and Transfer  
5. Database Services  
6. Network and System Management  
7. Application Frameworks  
8. VPN and Tunneling  
9. IoT and Embedded Systems  
10. Other Important Ports  
11. Scan All Ports  

Select a category by number: 1  

Port Scan Results for 192.168.1.103:  
  Port 80: Open  
  Port 443: Open  
  Port 8080: Closed  
  Port 8000: Closed  
  Port 8443: Closed  
```

---

## **Key Features in Detail**  
### **Network Discovery**  
- Uses system commands (`ipconfig`, `ifconfig`, etc.) to retrieve network details (local IP, gateway, subnet mask).  
- Pings each host in the network to identify active devices.  
- Resolves hostnames via reverse DNS lookup.

### **Port Scanning**  
- Categorized ports for quick scanning:  
  - **Web Services**: Ports like 80, 443, 8080.  
  - **SSH and Remote Access**: Ports like 22, 3389.  
  - And more...  
- Scan all ports across categories with a single command.

### **Cross-Platform Support**  
- Works on Windows, macOS, and Linux.  
- Automatically adapts system commands based on the operating system.

---

## **Known Issues**  
1. **Hostname Resolution**: Not all devices respond to reverse DNS lookups, resulting in "Unknown" for some hostnames.  
2. **Performance**: Scanning large networks or many ports can be slow due to the sequential nature of port scanning.  
3. **Limited Subnet Mask Detection**: Assumes a `/24` subnet mask if it cannot retrieve the actual subnet mask from the system.

---

## **Future Enhancements**  
1. **Custom Port Lists**:  
   - Allow users to input custom port ranges for scanning.

2. **Parallelized Port Scanning**:  
   - Use threading or multiprocessing to scan multiple ports simultaneously, improving performance for large scans.

3. **Export Results**:  
   - Save network scan and port scan results to a file (e.g., JSON, CSV) for reporting or further analysis.

4. **Custom Subnet Support**:  
   - Enable users to specify a custom subnet range for network scans.

5. **Enhanced Logging**:  
   - Add logging for network discovery and port scanning to a file for debugging and audit purposes.

6. **Additional Protocol Detection**:  
   - Integrate features to detect specific protocols or services (e.g., HTTP, SSH) running on open ports.

---

## **Contributing**  
If you'd like to contribute, please fork the repository, make changes, and submit a pull request. For major changes, please open an issue to discuss your ideas.

---

## **License**  
This project is licensed under the MIT License. See the LICENSE file for details.