
PROTOCOLS = {
    "HTTPS" : {
        "port": 443,
        "payload": "GET /index.html",
        "transport": "TCP"
    },
    "DNS" : {
        "port": 53,
        "payload": "Query: google.com",
        "transport": "UDP"
    }
}