KNOWN_EVENTS = {

    41: {
        "name": "Kernel-Power",
        "cause": "Unexpected shutdown",
        "severity": 95,
        "solutions": [
            "Check power supply",
            "Check CPU temperatures",
            "Check RAM stability",
            "Review events before Event ID 41"
        ]
    },

    6008: {
        "name": "Unexpected Shutdown",
        "cause": "System was not properly shut down",
        "severity": 85,
        "solutions": [
            "Review hardware",
            "Check UPS",
            "Check power source"
        ]
    },

    7: {
        "name": "Disk Error",
        "cause": "Bad sectors detected",
        "severity": 95,
        "solutions": [
            "Run CHKDSK",
            "Check SMART status",
            "Replace disk if necessary"
        ]
    },

    55: {
        "name": "NTFS Corruption",
        "cause": "File system corruption",
        "severity": 90,
        "solutions": [
            "Run CHKDSK /F",
            "Verify disk health"
        ]
    },

    10016: {
        "name": "DistributedCOM",
        "cause": "Permission issue",
        "severity": 35,
        "solutions": [
            "Review DCOM permissions"
        ]
    }
}