# Log Analysis Script

## Overview

The **Log Analysis Script** is a Python-based utility designed to process server log files, analyze them for specific patterns, and extract actionable insights. It includes functionalities like counting requests per IP address, identifying the most accessed endpoints, and detecting suspicious activity, such as potential brute force login attempts.

---

## Features

1. **Requests Per IP Address**:
   - Extracts all IP addresses from the log file.
   - Counts and displays the number of requests made by each IP address in descending order.

2. **Most Accessed Endpoint**:
   - Identifies the endpoint (e.g., URLs or resource paths) accessed the highest number of times.
   - Displays the endpoint name and its access count.

3. **Suspicious Activity Detection**:
   - Flags IP addresses with failed login attempts exceeding a configurable threshold (default: 1 attempts).
   - Supports detection using HTTP status code `401` or the presence of the phrase "Invalid credentials."

4. **Output Results**:
   - Displays results in the terminal for quick review.
   - Saves results in a structured CSV file named `log_analysis_results.csv` for further analysis.

---

## Prerequisites

- Python 3.x installed on your system.
- A log file (`sample.log`) in a compatible format.

---

## Installation

1. Clone the repository or download the script file.
2. Ensure Python 3.x is installed by running:
   ```bash
   python --version
