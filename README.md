SDN Testbed with Traffic Classification

This thesis is an implementation of a Software Defined Networking (SDN) testbed for network traffic classification. It was developed as part of my thesis work, focusing on using SDN controllers for monitoring and classifying network traffic flows.

Key Components:
Ryu SDN Controller: This code uses the Ryu framework to handle SDN functionality, manage network flows, and monitor network metrics.

Traffic Collection & Monitoring: The application collects network statistics such as byte and packet counts, and computes flow rates for both forward and reverse traffic.

Traffic Classification: The testbed is equipped to classify different types of network traffic (e.g., Ping, Telnet, VoIP, DNS) and log the results into a CSV file.

Flow Monitoring: Monitors flows dynamically, calculates packet and byte rates, and can store or classify this information for further analysis.


How It Works:

Flow Monitoring: The SDN controller requests flow statistics from connected OpenFlow switches at regular intervals.

Traffic Metrics: Byte and packet rates are calculated for both forward and reverse flows and logged to a CSV for data collection or traffic analysis.

Customizable for Machine Learning: The system can be extended to include machine learning models for real-time traffic classification and detection.

This code provides a scalable framework for building SDN-based network traffic classification systems, useful for network monitoring and optimization.
