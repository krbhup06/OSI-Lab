
PROTOCOLS = {
    "HTTPS" : {
        "port": 443,
        "payload": "GET /index.html",
        "transport": "TCP",
        "protocol_number": 6
    },
    "DNS" : {
        "port": 53,
        "payload": "Query: google.com",
        "transport": "UDP",
        "protocol_number": 17
    }
}