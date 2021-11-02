from random import randint


def is_prime(p, tries=10):
    """Miller Rabin Test"""
    if p < 3:
        return p == 2
    q = p - 1
    t = 0

    while q % 2 == 0:
        q //= 2
        t += 1

    for _ in range(tries):
        a = randint(2, p - 1)
        v = pow(a, q, p)
        if v == 1 or v == p - 1:
            continue
        for j in range(t + 1):
            v = v * v % p
            if v == p - 1:
                break
        else:
            return False
    return True


if __name__ == '__main__':
    n = int(input('number: '))

    if is_prime(n):
        print(f'{n} is prime')
    else:
        print(f'{n} is composite')
