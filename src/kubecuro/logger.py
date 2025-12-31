import logging

def get_logger():
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    return logging.getLogger("KubeCuro")
