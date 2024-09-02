# Network Intrusion Detection System

Network Intrusion Detection System: This tool features real-time packet analysis with a user-friendly GUI, customizable intrusion pattern detection, and alerts for suspicious activity, all while supporting efficient multi-threaded processing for enhanced network security monitoring.

## Features

- **Real-Time Packet Analysis**
  - **Description:** Continuously captures and analyzes network packets to detect potential intrusions and suspicious activities.
  - **Benefit:** Provides immediate insights into network traffic, helping to identify and respond to threats in real-time.

- **Customizable Intrusion Detection Patterns**
  - **Description:** Allows users to define specific patterns and rules for detecting unusual or unauthorized network activities, such as traffic on non-standard ports or potential port scans.
  - **Benefit:** Enhances detection accuracy by targeting known threats and abnormal behaviors.

- **User-Friendly GUI**
  - **Description:** Built using Tkinter, the graphical user interface provides an intuitive and accessible way to start and manage network monitoring.
  - **Benefit:** Simplifies the setup and operation of the intrusion detection system, making it accessible to users with varying technical backgrounds.

- **Real-Time Alerts and Notifications**
  - **Description:** Provides immediate feedback on detected suspicious activities by displaying alerts in the GUI.
  - **Benefit:** Enables swift action in response to potential security threats, reducing the risk of security breaches.

- **Multi-Threaded Processing**
  - **Description:** Utilizes threading to handle packet sniffing and analysis in parallel, improving performance and responsiveness.
  - **Benefit:** Ensures efficient processing of network traffic without lag, even during high-traffic periods.

- **Error Handling and Notifications**
  - **Description:** Includes mechanisms for handling and displaying errors or issues encountered during packet analysis.
  - **Benefit:** Provides clear feedback and helps troubleshoot issues quickly, ensuring the system runs smoothly.

## Usage

- **Setup and Initialization**
  - **Install Dependencies:** Ensure that Python, Tkinter, and Scapy are installed on your system.
  - **Run the Code:** Execute the script to launch the graphical user interface (GUI).

- **Starting Network Monitoring**
  - **Open the GUI:** Launch the application to access the main interface.
  - **Start Monitoring:** Click the "Start Monitoring" button to begin capturing and analyzing network packets.

- **Configuring Detection Patterns**
  - **Add Custom Patterns:** Modify the `KNOWN_PATTERNS` list in the code to include specific patterns or port numbers relevant to your network security needs.

- **Viewing Results**
  - **Monitor Alerts:** Watch the GUI for real-time alerts and messages about detected suspicious activities.
  - **Analyze Packets:** Review the captured packet summaries and alerts to understand network behavior and potential threats.

- **Stopping Monitoring**
  - **Terminate the Program:** Close the application window to stop the packet sniffing and monitoring processes.

## Example Scenario

- If you want to monitor network traffic for unusual HTTP activity on non-standard ports or possible SSH port scans, you would configure the `KNOWN_PATTERNS` to include these criteria. Once you start monitoring, the system will capture network packets, analyze them based on your patterns, and alert you if any matches are found.

- This detailed approach ensures that the Network Intrusion Detection System provides effective and user-friendly network security monitoring, helping you stay informed and protected against potential threats.
