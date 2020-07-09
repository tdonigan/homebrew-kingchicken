import os

def sample_path(filename):
    return os.path.join(os.path.dirname(__file__), 'sample_data', filename)

def sample_file(filename):
    return open(sample_path(filename), 'rb')

def sample_data(filename):
    with sample_file(filename) as f:
        return f.read()

