class packet:
    def __init__(self, type, src_ip, dest_ip, data):
        self.type = type
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.data = data
