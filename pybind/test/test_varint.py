from pycryptonote import varint


def test_serialize_varint():
    for data in range(1, 100000):
        data_bytes = varint.write(data)
        data_int, read = varint.read(data_bytes)
        assert data_int == data
        assert read == len(data_bytes)

if __name__ == '__main__':
    test_serialize_varint()
