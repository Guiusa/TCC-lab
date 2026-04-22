#! /bin/bash

echo "192.168.100.20,2,127" \
> iprep/reputation.list

echo '{

    "window_size": 5,
    "hosts": [
        {
            "ip": "192.168.100.20",
            "rep": 128,
            "m": 19.2,
            "rep_history": [
                0,
                0,
                0,
                0,
                128
            ]
        }
    ]
}' > iprep/reputation.json
