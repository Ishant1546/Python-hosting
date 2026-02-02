#!/usr/bin/env python3
"""
Helper script to start everything
Run this if you want to start master.py separately
"""
import subprocess
import sys
import os

def start_master():
    """Start the master script"""
    print("Starting Python Script Host Master...")
    subprocess.Popen([sys.executable, "master.py"])

def create_example_scripts():
    """Create example scripts if none exist"""
    scripts_dir = "scripts"
    if not os.path.exists(scripts_dir) or len(os.listdir(scripts_dir)) == 0:
        print("Creating example scripts...")
        
        # Create data_processor example
        data_processor = '''#!/usr/bin/env python3
"""
Example Data Processor Script
"""
import time
import random
from datetime import datetime

print("Data Processor Started!")
print(f"Started at: {datetime.now()}")

def process_batch(batch_num):
    """Process a batch of data"""
    print(f"Processing batch {batch_num}...")
    time.sleep(2)
    records = random.randint(100, 1000)
    print(f"Batch {batch_num} complete: Processed {records} records")
    return records

try:
    batch = 0
    total_records = 0
    
    while True:
        batch += 1
        records = process_batch(batch)
        total_records += records
        
        print(f"Total records processed: {total_records}")
        print("Waiting 5 seconds before next batch...\\n")
        time.sleep(5)
        
except KeyboardInterrupt:
    print("\\nData Processor shutting down...")
    print(f"Final total: {total_records} records processed in {batch} batches")
'''
        
        os.makedirs("scripts/data_processor", exist_ok=True)
        with open("scripts/data_processor/script.py", "w") as f:
            f.write(data_processor)
        
        print("Example script created: scripts/data_processor/script.py")

if __name__ == "__main__":
    create_example_scripts()
    start_master()
    print("Master script started. Access at http://localhost:10000")
    print("Default login: admin / admin123")