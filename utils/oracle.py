
def get_block(buffer, block_size, index):
    return buffer[block_size * index: block_size * (index + 1)]

def is_ECB_encrypted(ciphertext, block_size):
    block_count = int(len(ciphertext) / block_size)

    # Test each block against every block that follow it:
    # if they are the same, ciphertext is ECB encoded.
    for i in range(block_count - 1):
        focus_block = get_block(ciphertext, block_size, i)
        for j in range(i + 1, block_count):
            if focus_block == get_block(ciphertext, block_size, j):
                return True
    return False
